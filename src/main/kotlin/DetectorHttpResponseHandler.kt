package rain

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.proxy.http.InterceptedResponse

class DetectorHttpResponseHandler(private val api: MontoyaApi) : ProxyResponseHandler
{
    override fun handleResponseReceived(interceptedResponse: InterceptedResponse?): ProxyResponseReceivedAction {
        // 当Burp Suite代理接收到来自目标服务器的HTTP响应时触发,如增加解密流程以在bp显示明文等


        return ProxyResponseReceivedAction.continueWith(interceptedResponse)
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse?): ProxyResponseToBeSentAction {
        // 当Burp Suite代理准备将响应发送给客户端（浏览器）之前触发，如修改响应体字段 islogin=true
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }
}
