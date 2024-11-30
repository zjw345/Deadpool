package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)
const maxRetries = 3 // 最大重试次数
// 防止goroutine 异步处理问题
var addSocksMu sync.Mutex
var currentProxy string // 当前使用的代理
var Timeout = 10 // 设置超时时间为10秒


func addSocks(socks5 string) {
	addSocksMu.Lock()
	SocksList = append(SocksList, socks5)
	addSocksMu.Unlock()
}
func fetchContent(baseURL string, method string, timeout int, urlParams map[string]string, headers map[string]string, jsonBody string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if urlParams != nil {
		q := u.Query()
		for key, value := range urlParams {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
	}

	var req *http.Request
	if jsonBody != "" {
		req, err = http.NewRequest(method, u.String(), bytes.NewBufferString(jsonBody))
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}

	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
	if len(headers) != 0 {
		for key, value := range headers {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func RemoveDuplicates(list *[]string) {
	seen := make(map[string]struct{})
	var result []string
	for _, sock := range *list {
		if _, ok := seen[sock]; !ok {
			result = append(result, sock)
			seen[sock] = struct{}{}
		}
	}

	*list = result
}

func CheckSocks(checkSocks CheckSocksConfig, socksListParam []string) {
	startTime := time.Now()
	maxConcurrentReq := checkSocks.MaxConcurrentReq
	timeout := checkSocks.Timeout
	semaphore = make(chan struct{}, maxConcurrentReq)

	checkRspKeywords := checkSocks.CheckRspKeywords
	checkGeolocateConfig := checkSocks.CheckGeolocate
	checkGeolocateSwitch := checkGeolocateConfig.Switch
	isOpenGeolocateSwitch := false
	reqUrl := checkSocks.CheckURL
	if checkGeolocateSwitch == "open" {
		isOpenGeolocateSwitch = true
		reqUrl = checkGeolocateConfig.CheckURL
	}
	fmt.Printf("时间:[ %v ] 并发:[ %v ],超时标准:[ %vs ]\n", time.Now().Format("2006-01-02 15:04:05"), maxConcurrentReq, timeout)
	var num int
	total := len(socksListParam)
	var tmpEffectiveList []string
	var tmpMu sync.Mutex
	for _, proxyAddr := range socksListParam {

		Wg.Add(1)
		semaphore <- struct{}{}
		go func(proxyAddr string) {
			tmpMu.Lock()
			num++
			fmt.Printf("\r正检测第 [ %v/%v ] 个代理,异步处理中...                    ", num, total)
			tmpMu.Unlock()
			defer Wg.Done()
			defer func() {
				<-semaphore

			}()
			socksProxy := "socks5://" + proxyAddr
			proxy := func(_ *http.Request) (*url.URL, error) {
				return url.Parse(socksProxy)
			}
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           proxy,
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeout) * time.Second,
			}
			req, err := http.NewRequest("GET", reqUrl, nil)
			if err != nil {
				return
			}
			req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
			req.Header.Add("referer", "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&tn=baidu&wd=ip&fenlei=256&rsv_pq=0xc23dafcc00076e78&rsv_t=6743gNBuwGYWrgBnSC7Yl62e52x3CKQWYiI10NeKs73cFjFpwmqJH%2FOI%2FSRG&rqlang=en&rsv_dl=tb&rsv_enter=1&rsv_sug3=5&rsv_sug1=5&rsv_sug7=101&rsv_sug2=0&rsv_btype=i&prefixsug=ip&rsp=4&inputT=2165&rsv_sug4=2719")
			resp, err := client.Do(req)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				// fmt.Printf("+++++++代理不可用：%v+++++++\n", proxyAddr)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				return
			}
			stringBody := string(body)
			if !isOpenGeolocateSwitch {
				if !strings.Contains(stringBody, checkRspKeywords) {
					return
				}
			} else {
				//直接循环要排除的关键字，任一命中就返回
				for _, keyword := range checkGeolocateConfig.ExcludeKeywords {
					if strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "包含：" + keyword.(string))
						return
					}
				}
				//直接循环要必须包含的关键字，任一未命中就返回
				for _, keyword := range checkGeolocateConfig.IncludeKeywords {
					if !strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "未包含：" + keyword.(string))
						return
					}
				}

			}
			tmpMu.Lock()
			tmpEffectiveList = append(tmpEffectiveList, proxyAddr)
			tmpMu.Unlock()
		}(proxyAddr)
	}
	Wg.Wait()
	mu.Lock()
	EffectiveList = make([]string, len(tmpEffectiveList))
	copy(EffectiveList, tmpEffectiveList)
	proxyIndex = 0
	mu.Unlock()
	sec := int(time.Since(startTime).Seconds())
	if sec == 0 {
		sec = 1
	}
	fmt.Printf("\n根据配置规则检测完成,用时 [ %vs ] ,共发现 [ %v ] 个可用\n", sec, len(tmpEffectiveList))
}

func WriteLinesToFile() error {
	file, err := os.Create(LastDataFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range EffectiveList {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func DefineDial(ctx context.Context, network, address string) (net.Conn, error) {

	return transmitReqFromClient(network, address)
}



func transmitReqFromClient(network string, address string) (net.Conn, error) {
    for {
        tempProxy := getNextProxy()
        if tempProxy == "" {
            return nil, fmt.Errorf("没有可用代理")
        }
        fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "\t正在使用代理：" + tempProxy)

        timeout := time.Duration(Timeout) * time.Second
        dialer := &net.Dialer{
            Timeout: timeout,
        }

        // 重试机制
        for retries := 0; retries < maxRetries; retries++ {
            dialect, err := proxy.SOCKS5(network, tempProxy, nil, dialer)
            if err != nil {
                fmt.Printf("%s无效，尝试重试 [%d/%d]...\n", tempProxy, retries+1, maxRetries)
                continue // 直接进入下一次重试
            }

            conn, err := dialect.Dial(network, address)
            if err != nil {
                fmt.Printf("%s连接失败，尝试重试 [%d/%d]...\n", tempProxy, retries+1, maxRetries)
                continue // 直接进入下一次重试
            }

            // 成功返回连接
            return conn, nil
        }

        // 如果达到重试次数，移除无效代理
        fmt.Printf("%s达到最大重试次数，判定为无效，切换到下一个代理...\n", tempProxy)
        delInvalidProxy(tempProxy)
    }
}



func getNextProxy() string {
    mu.Lock()
    defer mu.Unlock()
    if len(EffectiveList) == 0 {
        fmt.Println("***已无可用代理，请重新运行程序***")
        return ""
    }
    if currentProxy == "" || !isProxyInList(currentProxy) {
        currentProxy = EffectiveList[proxyIndex]
    }
    return currentProxy
}

func isProxyInList(proxy string) bool {
    for _, p := range EffectiveList {
        if p == proxy {
            return true
        }
    }
    return false
}


// 使用过程中删除无效的代理
func delInvalidProxy(proxy string) {
    mu.Lock()
    defer mu.Unlock()
    for i, p := range EffectiveList {
        if p == proxy {
            EffectiveList = append(EffectiveList[:i], EffectiveList[i+1:]...)
            break
        }
    }
    if currentProxy == proxy {
        currentProxy = "" // 清空当前代理
    }
    if proxyIndex >= len(EffectiveList) {
        proxyIndex = 0
    }
}


func GetSocks(config Config) {
	GetSocksFromFile(LastDataFile)
	//从fofa获取
	Wg.Add(1)
	go GetSocksFromFofa(config.FOFA)
	//从hunter获取
	Wg.Add(1)
	go GetSocksFromHunter(config.HUNTER)
	//从quake中取
	Wg.Add(1)
	go GetSocksFromQuake(config.QUAKE)
	Wg.Wait()
	//根据IP:PORT去重，此步骤会存在同IP不同端口的情况，这种情况不再单独过滤，这种情况，最终的出口IP可能不一样
	RemoveDuplicates(&SocksList)
}
