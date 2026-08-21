//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jchv/go-webview2"
)

func runDesktop(a *Analyzer) error {
	page, err := embeddedPage()
	if err != nil {
		return err
	}
	profileDir, err := desktopProfileDir()
	if err != nil {
		return err
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{Debug: false, AutoFocus: true, DataPath: profileDir, WindowOptions: webview2.WindowOptions{Title: "无尽冬日 · 协议分析器", Width: 1440, Height: 900, Center: true}})
	if w == nil {
		return fmt.Errorf("WebView2 Runtime 未安装或初始化失败")
	}
	defer w.Destroy()
	if err := w.Bind("nativeAPI", a.nativeAPI); err != nil {
		return err
	}
	w.SetSize(1440, 900, webview2.HintNone)
	w.Init(`(function(){
const callNative=(url,method,body)=>nativeAPI(JSON.stringify([url,method||"GET",body||null]));
window.fetch=(url,options)=>callNative(String(url),options&&options.method,options&&options.body).then(body=>({ok:true,json:()=>Promise.resolve(JSON.parse(body)),text:()=>Promise.resolve(body)})).catch(error=>({ok:false,json:()=>Promise.resolve({ok:false,error:String(error&&error.message||error||"native bridge failed")}),text:()=>Promise.resolve(String(error&&error.message||error||"native bridge failed"))}));
window.EventSource=class{constructor(url){this.url=url;this.after=Number.MAX_SAFE_INTEGER;this.onmessage=null;this.onopen=null;this.onerror=null;this.timer=setInterval(()=>this.poll(),250);this.poll()}poll(){callNative(this.url+(this.url.includes("?")?"&":"?")+"after="+this.after).then(body=>{const data=JSON.parse(body);this.after=Number(data.latest_id||this.after);if(this.onopen){this.onopen();this.onopen=null}for(const item of(data.items||[])){if(this.onmessage)this.onmessage({data:JSON.stringify(item)})}}).catch(()=>{if(this.onerror)this.onerror()})}close(){clearInterval(this.timer)}};
})();`)
	w.SetHtml(page)
	w.Run()
	return nil
}

func desktopProfileDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve WebView2 cache directory: %w", err)
	}
	path := filepath.Join(base, "wjdr-analyzer", "webview2")
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("create WebView2 cache directory: %w", err)
	}
	return path, nil
}
