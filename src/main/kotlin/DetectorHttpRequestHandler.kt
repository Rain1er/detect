package rain

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.ContentType
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import rain.rce.Utils

class DetectorHttpRequestHandler(private val api: MontoyaApi) : ProxyRequestHandler {
    override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
        // 直接继续处理，不做任何修改
        return ProxyRequestReceivedAction.continueWith(interceptedRequest)
    }

    override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {

        // 检查是否命中缓存
        if (Utils.isCached(interceptedRequest.path())) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }

        // 注：以下对cookie同样进行了fuzz
        // 1. 如果有查询参数，那么注意逐个fuzz
        if (interceptedRequest.hasParameters() && interceptedRequest.method() == "GET") {
            // 使用 GlobalScope.launch 启动一个后台协程，不会阻塞当前线程
            GlobalScope.launch {
                delay(5000)
                Utils.fuzzQueryParameters(interceptedRequest, api)
            }
        }

        // 2. 如果有请求体，逐个fuzz value
        if (interceptedRequest.body().length() > 0 && interceptedRequest.method() == "POST") {
            val contentType = interceptedRequest.contentType()
            when {

                contentType == ContentType.URL_ENCODED -> {

                    GlobalScope.launch {
                        delay(5000)
                        Utils.fuzzFormBody(interceptedRequest, api)
                    }
                }

                contentType == ContentType.JSON -> {
                    GlobalScope.launch {
                        delay(5000)
                        Utils.fuzzJsonBody("",interceptedRequest, api)
                    }
                }
                contentType == ContentType.MULTIPART -> {
                    // TODO: 多表单处理
                }
            }
        }

        // 立即返回，让原始请求继续发送，fuzzing任务会在后台独立运行
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
    }
}