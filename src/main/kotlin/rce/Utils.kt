package rain.rce

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.http.InterceptedRequest
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import kotlinx.coroutines.*
import java.io.File
import java.net.URLDecoder
import java.util.concurrent.Executors

class Utils {
    // companion用于替代static，因为kotlin中没有static关键字
    companion object FuzzUtils {
        // 创建Payload实例以访问payload数据
        private val fuzz = Payload()
        // 控制并发线程数为50
        private val fuzzingDispatcher = Executors.newFixedThreadPool(50).asCoroutineDispatcher()

        // Fuzz查询参数
        suspend fun fuzzQueryParameters(request: InterceptedRequest, api: MontoyaApi) {
            coroutineScope {
                val parameters = request.parameters()
                parameters.forEach { param ->
                    if (param.type() == HttpParameterType.URL) {
                        // 使用 launch 启动并发任务，尝试执行id命令
                        fuzz.EchoInject.forEach { payload ->
                            launch(fuzzingDispatcher) {
                                val newParam = HttpParameter.parameter(param.name(), param.value() + payload, param.type())
                                val updatedRequest = request.withUpdatedParameters(newParam)
                                api.logging().logToOutput("GET: Fuzzing URL : " + updatedRequest.path())

                                val httpRequestResponse = sendRequestAsync(api, updatedRequest)
                                val responseBody = httpRequestResponse.response().bodyToString()
                                if (responseBody?.contains("uid=") == true) {
                                    api.organizer().sendToOrganizer(httpRequestResponse)
                                }
                            }
                        }

                        // 尝试OOB
                        fuzz.OOBInject.forEach { payload ->
                            launch(fuzzingDispatcher) {
                                val collaboratorClient = api.collaborator().createClient()
                                val collaboratorPayload = collaboratorClient.generatePayload()
                                val oobPayload = payload.replaceFirst("{{interactsh-url}}", collaboratorPayload.toString())
                                val newParamWithOOB = HttpParameter.parameter(param.name(), param.value() + oobPayload, param.type())
                                val updatedRequestWithOOB = request.withUpdatedParameters(newParamWithOOB)

                                val httpRequestResponse = sendRequestAsync(api, updatedRequestWithOOB)

                                // 使用 delay 替代 Thread.sleep，避免阻塞线程
                                delay(2000)

                                val interactions = collaboratorClient.getAllInteractions()
                                if (interactions.isNotEmpty()) {
                                    api.organizer().sendToOrganizer(httpRequestResponse)
                                }
                            }
                        }
                    }
                    // sleep 注入也并发执行
                    launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithBackquotes_2, fuzz.sleepInjectWithBackquotes_4) }
                    launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithSemicolon_2, fuzz.sleepInjectWithSemicolon_4) }
                    launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithSinglequotes_2, fuzz.sleepInjectWithSinglequotes_4) }
                    launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithDoublequotes_2, fuzz.sleepInjectWithDoublequotes_4) }
                }
            }
        }

        // Fuzz表单请求体
        suspend fun fuzzFormBody(request: InterceptedRequest, api: MontoyaApi) {
            coroutineScope {
                try {
                    val bodyString = request.bodyToString()
                    val params = parseFormData(bodyString)
                    params.forEach { (key, value) ->
                        // 支持特殊格式的表单数据，key={JSON对象}
                        // parameter={"License":{"consumer":"1","address":"1","zipCode":"1","contactor":"1","telphone":";sleep 5;","email":"1@qq.com","enabled":true}}
                        if (value.startsWith("{") && value.endsWith("}")) {
                            val prefix = "$key="
                            fuzzJsonBody(prefix, request, api)
                        }else {
                            // Echo-based fuzzing
                            fuzz.EchoInject.forEach { payload ->
                                launch(fuzzingDispatcher) {
                                    val newValue = value + payload
                                    val escapedNewValue = Regex.escapeReplacement("$key=$newValue")
                                    val newBody = bodyString.replaceFirst(Regex("$key=[^&]*"), escapedNewValue)
                                    api.logging().logToOutput("Fuzzing form param: $key = $newValue")

                                    val httpRequestResponse = sendRequestAsync(api, request.withBody(newBody))
                                    if (httpRequestResponse.response().bodyToString()?.contains("uid=") == true) {
                                        api.organizer().sendToOrganizer(httpRequestResponse)
                                    }
                                }
                            }

                            // OOB-based fuzzing
                            fuzz.OOBInject.forEach { payload ->
                                launch(fuzzingDispatcher) {
                                    val collaboratorClient = api.collaborator().createClient()
                                    val collaboratorPayload = collaboratorClient.generatePayload()
                                    val oobPayload = payload.replaceFirst("{{interactsh-url}}", collaboratorPayload.toString())
                                    val newValue = value + oobPayload
                                    val escapedNewValue = Regex.escapeReplacement("$key=$newValue")
                                    val newBody = bodyString.replaceFirst(Regex("$key=[^&]*"), escapedNewValue)
                                    api.logging().logToOutput("Fuzzing form param with OOB: $key = $newValue")

                                    val httpRequestResponse = sendRequestAsync(api, request.withBody(newBody))
                                    delay(2000)
                                    if (collaboratorClient.getAllInteractions().isNotEmpty()) {
                                        api.organizer().sendToOrganizer(httpRequestResponse)
                                    }
                                }
                            }
                        }
                        // Sleep-based fuzzing
                        launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithBackquotes_2, fuzz.sleepInjectWithBackquotes_4) }
                        launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithSemicolon_2, fuzz.sleepInjectWithSemicolon_4) }
                        launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithSinglequotes_2, fuzz.sleepInjectWithSinglequotes_4) }
                        launch(fuzzingDispatcher) { sleepInject(request, api, fuzz.sleepInjectWithDoublequotes_2, fuzz.sleepInjectWithDoublequotes_4) }
                        }
                } catch (e: Exception) {
                    api.logging().logToOutput("Error parsing form data: ${e.message}")
                }
            }
        }

        // 解析表单数据
        fun parseFormData(body: String): Map<String, String> {
            return body.split("&").associate { param ->
                val parts = param.split("=", limit = 2)
                if (parts.size == 2) {
                    URLDecoder.decode(parts[0], "UTF-8") to URLDecoder.decode(parts[1], "UTF-8")
                } else {
                    parts[0] to ""
                }
            }
        }

        suspend fun sleepInject(request: InterceptedRequest, api: MontoyaApi, time_2: List<String>, time_3: List<String>) {
            coroutineScope {
                val parameters = request.parameters()
                parameters.forEach { param ->
                    time_2.forEach { payload ->
                        launch(fuzzingDispatcher) {
                            val newParam = HttpParameter.parameter(param.name(), param.value() + payload, param.type())
                            val updatedRequest = request.withUpdatedParameters(newParam)
                            api.logging().logToOutput("POST: Fuzzing URL : " + updatedRequest.path())

                            val startTime = System.currentTimeMillis()
                            sendRequestAsync(api, updatedRequest)
                            val timeElapsed = System.currentTimeMillis() - startTime

                            if (timeElapsed in 2000..7000) {
                                // 启动第二个确认请求
                                time_3.forEach { secondPayload ->
                                    launch(fuzzingDispatcher) {
                                        val newParamWithSleep = HttpParameter.parameter(param.name(), param.value() + secondPayload, param.type())
                                        val updatedRequest_ = request.withUpdatedParameters(newParamWithSleep)
                                        api.logging().logToOutput("POST: Fuzzing URL (Confirm) : " + updatedRequest_.path())

                                        val secondStartTime = System.currentTimeMillis()
                                        val httpRequestResponse = sendRequestAsync(api, updatedRequest_)
                                        val secondTimeElapsed = System.currentTimeMillis() - secondStartTime

                                        if ( secondTimeElapsed in 4000..13000 && secondTimeElapsed-timeElapsed > 2000) {
                                            api.organizer().sendToOrganizer(httpRequestResponse)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fuzz JSON请求体
        suspend fun fuzzJsonBody(prefix: String = "", request: InterceptedRequest, api: MontoyaApi) {
            coroutineScope {
                try {
                    val mapper = ObjectMapper()
                    val body = URLDecoder.decode(request.bodyToString().replace("$prefix", ""), "UTF-8")
                    val jsonNode = mapper.readTree(body)

                    if (jsonNode.isObject) {
                        val objectNode = jsonNode as ObjectNode

                        // Echo-based fuzzing
                        val echoResults = fuzzJsonObjectWithEcho(objectNode, mapper, api, request)
                        echoResults.forEach { modifiedJson ->
                            launch(fuzzingDispatcher) {
                                val newBody = mapper.writeValueAsString(modifiedJson)
                                val updatedRequest = request.withBody(prefix+newBody)
                                val httpRequestResponse = sendRequestAsync(api, updatedRequest)
                                if (httpRequestResponse.response().bodyToString()?.contains("uid=") == true) {
                                    api.organizer().sendToOrganizer(httpRequestResponse)
                                }
                            }
                        }

                        // OOB-based fuzzing
                        val oobResults = fuzzJsonObjectWithOOB(objectNode, mapper, api, request)
                        oobResults.forEach { (modifiedJson, collaboratorClient) ->
                            launch(fuzzingDispatcher) {
                                val newBody = mapper.writeValueAsString(modifiedJson)
                                val updatedRequest = request.withBody(prefix+newBody)
                                val httpRequestResponse = sendRequestAsync(api, updatedRequest)
                                delay(2000)
                                if (collaboratorClient.getAllInteractions().isNotEmpty()) {
                                    api.organizer().sendToOrganizer(httpRequestResponse)
                                }
                            }
                        }

                        // Sleep-based fuzzing
                        launch { sleepInjectJson(prefix,objectNode, mapper, api, request, fuzz.sleepInjectWithBackquotes_2, fuzz.sleepInjectWithBackquotes_4) }
                        launch { sleepInjectJson(prefix,objectNode, mapper, api, request, fuzz.sleepInjectWithSemicolon_2, fuzz.sleepInjectWithSemicolon_4) }
                        launch { sleepInjectJson(prefix,objectNode, mapper, api, request, fuzz.sleepInjectWithSinglequotes_2, fuzz.sleepInjectWithSinglequotes_4) }
                        launch { sleepInjectJson(prefix,objectNode, mapper, api, request, fuzz.sleepInjectWithDoublequotes_2, fuzz.sleepInjectWithDoublequotes_4) }

                    } else {
                        api.logging().logToOutput("Request body is not a valid JSON object.")
                    }
                } catch (e: Exception) {
                    api.logging().logToOutput("Error parsing JSON: ${e.message}")
                }
            }
        }

        // Echo-based JSON fuzzing
        fun fuzzJsonObjectWithEcho(
            objectNode: ObjectNode,
            mapper: ObjectMapper,
            api: MontoyaApi,
            request: InterceptedRequest
        ): List<ObjectNode> {
            val results = mutableListOf<ObjectNode>()

            objectNode.fieldNames().asSequence().forEach { fieldName: String ->
                val fieldValue = objectNode.get(fieldName)

                when {
                    fieldValue.isTextual -> {
                        // 为每个payload创建单独的变异
                        fuzz.EchoInject.forEach { payload ->
                            val result = objectNode.deepCopy()
                            val originalValue = fieldValue.asText()
                            val newValue = originalValue + payload
                            result.put(fieldName, newValue)
                            results.add(result)

                            api.logging().logToOutput("Echo fuzzing JSON field: $fieldName = $newValue")
                        }
                    }

                    fieldValue.isObject -> {
                        // 递归处理嵌套对象
                        val nestedResults = fuzzJsonObjectWithEcho(fieldValue as ObjectNode, mapper, api, request)
                        nestedResults.forEach { nestedResult ->
                            val result = objectNode.deepCopy()
                            result.set<JsonNode>(fieldName, nestedResult)
                            results.add(result)
                        }
                    }

                    fieldValue.isArray -> {
                        // 处理数组中的所有字符串元素
                        val arrayNode = fieldValue
                        for (i in 0 until arrayNode.size()) {
                            val arrayElement = arrayNode.get(i)
                            when {
                                arrayElement.isTextual -> {
                                    // 对数组中的字符串元素进行fuzz
                                    fuzz.EchoInject.forEach { payload ->
                                        val result = objectNode.deepCopy()
                                        val resultArray = result.get(fieldName) as ArrayNode
                                        val originalValue = arrayElement.asText()
                                        val newValue = originalValue + payload
                                        resultArray.set(i, mapper.valueToTree(newValue))
                                        results.add(result)

                                        api.logging()
                                            .logToOutput("Echo fuzzing JSON array field: $fieldName[$i] = $newValue")
                                    }
                                }

                                arrayElement.isObject -> {
                                    // 递归处理数组中的对象
                                    val nestedResults =
                                        fuzzJsonObjectWithEcho(arrayElement as ObjectNode, mapper, api, request)
                                    nestedResults.forEach { nestedResult ->
                                        val result = objectNode.deepCopy()
                                        val resultArray = result.get(fieldName) as ArrayNode
                                        resultArray.set(i, nestedResult)
                                        results.add(result)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return results
        }

        // OOB-based JSON fuzzing
        fun fuzzJsonObjectWithOOB(
            objectNode: ObjectNode,
            mapper: ObjectMapper,
            api: MontoyaApi,
            request: InterceptedRequest
        ): List<Pair<ObjectNode, CollaboratorClient>> {
            val results = mutableListOf<Pair<ObjectNode, CollaboratorClient>>()

            objectNode.fieldNames().asSequence().forEach { fieldName: String ->
                val fieldValue = objectNode.get(fieldName)

                when {
                    // value是字符串
                    fieldValue.isTextual -> {
                        // 为每个payload创建单独的变异
                        fuzz.OOBInject.forEach { payload ->
                            val collaboratorClient = api.collaborator().createClient()
                            val collaboratorPayload = collaboratorClient.generatePayload()
                            val oobPayload = payload.replaceFirst("{{interactsh-url}}", collaboratorPayload.toString())

                            val result = objectNode.deepCopy()
                            val originalValue = fieldValue.asText()
                            val newValue = originalValue + oobPayload
                            result.put(fieldName, newValue)
                            results.add(Pair(result, collaboratorClient))

                            api.logging().logToOutput("OOB fuzzing JSON field: $fieldName = $newValue")
                        }
                    }

                    // value是对象
                    fieldValue.isObject -> {
                        // 递归处理嵌套对象
                        val nestedResults = fuzzJsonObjectWithOOB(fieldValue as ObjectNode, mapper, api, request)
                        nestedResults.forEach { (nestedResult, collaboratorClient) ->
                            val result = objectNode.deepCopy()
                            result.set<JsonNode>(fieldName, nestedResult)
                            results.add(Pair(result, collaboratorClient))
                        }
                    }

                    // value是数组
                    fieldValue.isArray -> {
                        // 处理数组中的所有字符串元素
                        val arrayNode = fieldValue
                        for (i in 0 until arrayNode.size()) {
                            val arrayElement = arrayNode.get(i)
                            when {
                                arrayElement.isTextual -> {
                                    // 对数组中的字符串元素进行fuzz
                                    fuzz.OOBInject.forEach { payload ->
                                        val collaboratorClient = api.collaborator().createClient()
                                        val collaboratorPayload = collaboratorClient.generatePayload()
                                        val oobPayload =
                                            payload.replaceFirst("{{interactsh-url}}", collaboratorPayload.toString())

                                        val result = objectNode.deepCopy()
                                        val resultArray = result.get(fieldName) as ArrayNode
                                        val originalValue = arrayElement.asText()
                                        val newValue = originalValue + oobPayload
                                        resultArray.set(i, mapper.valueToTree(newValue))
                                        results.add(Pair(result, collaboratorClient))

                                        api.logging()
                                            .logToOutput("OOB fuzzing JSON array field: $fieldName[$i] = $newValue")
                                    }
                                }

                                arrayElement.isObject -> {
                                    // 递归处理数组中的对象
                                    val nestedResults =
                                        fuzzJsonObjectWithOOB(arrayElement as ObjectNode, mapper, api, request)
                                    nestedResults.forEach { (nestedResult, collaboratorClient) ->
                                        val result = objectNode.deepCopy()
                                        val resultArray = result.get(fieldName) as ArrayNode
                                        resultArray.set(i, nestedResult)
                                        results.add(Pair(result, collaboratorClient))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return results
        }


        // Sleep injection for JSON
        suspend fun sleepInjectJson(
            prefix: String = "",
            objectNode: ObjectNode,
            mapper: ObjectMapper,
            api: MontoyaApi,
            request: InterceptedRequest,
            time_2: List<String>,
            time_3: List<String>
        ) {
            coroutineScope {
                objectNode.fieldNames().asSequence().forEach { fieldName: String ->
                    val fieldValue = objectNode.get(fieldName)

                    when {
                        fieldValue.isTextual -> {
                            time_2.forEach { payload ->
                                launch(fuzzingDispatcher) {
                                    val result = objectNode.deepCopy()
                                    val originalValue = fieldValue.asText()
                                    val newValue = originalValue + payload
                                    result.put(fieldName, newValue)

                                    val newBody = mapper.writeValueAsString(result)
                                    val updatedRequest = request.withBody(prefix + newBody)

                                    api.logging().logToOutput("Sleep fuzzing JSON field: $fieldName = $newValue")

                                    // 发送修改后的请求并统计时间
                                    val startTime = System.currentTimeMillis()
                                    sendRequestAsync(api, updatedRequest)
                                    val endTime = System.currentTimeMillis()
                                    val timeElapsed = endTime - startTime

                                    if (timeElapsed in 2000..7000) {
                                        time_3.forEach { secondPayload ->
                                            launch(fuzzingDispatcher) {
                                                val secondResult = objectNode.deepCopy()
                                                val secondValue = originalValue + secondPayload
                                                secondResult.put(fieldName, secondValue)

                                                val secondBody = mapper.writeValueAsString(secondResult)
                                                val secondUpdatedRequest = request.withBody(prefix + secondBody)

                                                api.logging()
                                                    .logToOutput("Sleep fuzzing JSON field (confirmation): $fieldName = $secondValue")

                                                // 发送确认请求并统计时间
                                                val secondStartTime = System.currentTimeMillis()
                                                val httpRequestResponse = sendRequestAsync(api, secondUpdatedRequest)
                                                val secondEndTime = System.currentTimeMillis()
                                                val secondTimeElapsed = secondEndTime - secondStartTime

                                                // 如果两次都有延迟，则认为存在漏洞
                                                if ( secondTimeElapsed in 4000..13000 && secondTimeElapsed-timeElapsed > 2000) {
                                                    api.organizer().sendToOrganizer(httpRequestResponse)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        fieldValue.isObject -> {
                            // 递归处理嵌套对象 - 修复：正确处理嵌套结构
                            val nestedObjectNode = fieldValue as ObjectNode
                            nestedObjectNode.fieldNames().asSequence().forEach { nestedFieldName ->
                                val nestedFieldValue = nestedObjectNode.get(nestedFieldName)
                                
                                when {
                                    nestedFieldValue.isTextual -> {
                                        time_2.forEach { payload ->
                                            launch(fuzzingDispatcher) {
                                                val result = objectNode.deepCopy()
                                                val nestedResult = result.get(fieldName) as ObjectNode
                                                val originalValue = nestedFieldValue.asText()
                                                val newValue = originalValue + payload
                                                nestedResult.put(nestedFieldName, newValue)

                                                val newBody = mapper.writeValueAsString(result)
                                                val updatedRequest = request.withBody(prefix + newBody)

                                                api.logging().logToOutput("Sleep fuzzing nested JSON field: $fieldName.$nestedFieldName = $newValue")

                                                // 发送修改后的请求并统计时间
                                                val startTime = System.currentTimeMillis()
                                                sendRequestAsync(api, updatedRequest)
                                                val endTime = System.currentTimeMillis()
                                                val timeElapsed = endTime - startTime

                                                if (timeElapsed in 2000..7000) {
                                                    time_3.forEach { secondPayload ->
                                                        launch(fuzzingDispatcher) {
                                                            val secondResult = objectNode.deepCopy()
                                                            val secondNestedResult = secondResult.get(fieldName) as ObjectNode
                                                            val secondValue = originalValue + secondPayload
                                                            secondNestedResult.put(nestedFieldName, secondValue)

                                                            val secondBody = mapper.writeValueAsString(secondResult)
                                                            val secondUpdatedRequest = request.withBody(prefix + secondBody)

                                                            api.logging()
                                                                .logToOutput("Sleep fuzzing nested JSON field (confirmation): $fieldName.$nestedFieldName = $secondValue")

                                                            // 发送确认请求并统计时间
                                                            val secondStartTime = System.currentTimeMillis()
                                                            val httpRequestResponse = sendRequestAsync(api, secondUpdatedRequest)
                                                            val secondEndTime = System.currentTimeMillis()
                                                            val secondTimeElapsed = secondEndTime - secondStartTime

                                                            // 如果两次都有延迟且满足一定条件，则认为存在漏洞
                                                            if ( secondTimeElapsed in 4000..13000 && secondTimeElapsed-timeElapsed > 2000) {
                                                                api.organizer().sendToOrganizer(httpRequestResponse)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    nestedFieldValue.isObject -> {
                                        // 递归处理更深层嵌套对象
                                        launch(fuzzingDispatcher) { 
                                            sleepInjectJson(prefix, nestedFieldValue as ObjectNode, mapper, api, request, time_2, time_3) 
                                        }
                                    }
                                    
                                    nestedFieldValue.isArray -> {
                                        // 处理嵌套对象中的数组
                                        val nestedArrayNode = nestedFieldValue
                                        for (i in 0 until nestedArrayNode.size()) {
                                            val arrayElement = nestedArrayNode.get(i)
                                            when {
                                                arrayElement.isTextual -> {
                                                    time_2.forEach { payload ->
                                                        launch(fuzzingDispatcher) {
                                                            val result = objectNode.deepCopy()
                                                            val nestedResult = result.get(fieldName) as ObjectNode
                                                            val resultArray = nestedResult.get(nestedFieldName) as ArrayNode
                                                            val originalValue = arrayElement.asText()
                                                            val newValue = originalValue + payload
                                                            resultArray.set(i, mapper.valueToTree(newValue))

                                                            val newBody = mapper.writeValueAsString(result)
                                                            val updatedRequest = request.withBody(prefix + newBody)

                                                            api.logging()
                                                                .logToOutput("Sleep fuzzing nested JSON array field: $fieldName.$nestedFieldName[$i] = $newValue")

                                                            val startTime = System.currentTimeMillis()
                                                            sendRequestAsync(api, updatedRequest)
                                                            val timeElapsed = System.currentTimeMillis() - startTime

                                                            if (timeElapsed in 2000..7000) {
                                                                time_3.forEach { secondPayload ->
                                                                    launch(fuzzingDispatcher) {
                                                                        val secondResult = objectNode.deepCopy()
                                                                        val secondNestedResult = secondResult.get(fieldName) as ObjectNode
                                                                        val secondArray = secondNestedResult.get(nestedFieldName) as ArrayNode
                                                                        val secondValue = originalValue + secondPayload
                                                                        secondArray.set(i, mapper.valueToTree(secondValue))

                                                                        val secondBody = mapper.writeValueAsString(secondResult)
                                                                        val secondUpdatedRequest = request.withBody(prefix + secondBody)

                                                                        api.logging()
                                                                            .logToOutput("Sleep fuzzing nested JSON array field (confirmation): $fieldName.$nestedFieldName[$i] = $secondValue")

                                                                        val secondStartTime = System.currentTimeMillis()
                                                                        val httpRequestResponse = sendRequestAsync(api, secondUpdatedRequest)
                                                                        val secondTimeElapsed = System.currentTimeMillis() - secondStartTime

                                                                        if ( secondTimeElapsed in 4000..13000 && secondTimeElapsed-timeElapsed > 2000) {
                                                                            api.organizer().sendToOrganizer(httpRequestResponse)
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                
                                                arrayElement.isObject -> {
                                                    // 递归处理数组中的对象
                                                    launch(fuzzingDispatcher) { 
                                                        sleepInjectJson(prefix, arrayElement as ObjectNode, mapper, api, request, time_2, time_3) 
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        fieldValue.isArray -> {
                            // 处理数组中的所有字符串元素
                            val arrayNode = fieldValue
                            for (i in 0 until arrayNode.size()) {
                                val arrayElement = arrayNode.get(i)
                                when {
                                    arrayElement.isTextual -> {
                                        time_2.forEach { payload ->
                                            launch(fuzzingDispatcher) {
                                                val result = objectNode.deepCopy()
                                                val resultArray = result.get(fieldName) as ArrayNode
                                                val originalValue = arrayElement.asText()
                                                val newValue = originalValue + payload
                                                resultArray.set(i, mapper.valueToTree(newValue))

                                                val newBody = mapper.writeValueAsString(result)
                                                val updatedRequest = request.withBody(prefix + newBody)

                                                api.logging()
                                                    .logToOutput("Sleep fuzzing JSON array field: $fieldName[$i] = $newValue")

                                                val startTime = System.currentTimeMillis()
                                                sendRequestAsync(api, updatedRequest)
                                                val timeElapsed = System.currentTimeMillis() - startTime

                                                if (timeElapsed in 2000..7000) {
                                                    time_3.forEach { secondPayload ->
                                                        launch(fuzzingDispatcher) {
                                                            val secondResult = objectNode.deepCopy()
                                                            val secondArray = secondResult.get(fieldName) as ArrayNode
                                                            val secondValue = originalValue + secondPayload
                                                            secondArray.set(i, mapper.valueToTree(secondValue))

                                                            val secondBody = mapper.writeValueAsString(secondResult)
                                                            val secondUpdatedRequest = request.withBody(prefix + secondBody)

                                                            api.logging()
                                                                .logToOutput("Sleep fuzzing JSON array field (confirmation): $fieldName[$i] = $secondValue")

                                                            val secondStartTime = System.currentTimeMillis()
                                                            val httpRequestResponse = sendRequestAsync(api, secondUpdatedRequest)
                                                            val secondTimeElapsed = System.currentTimeMillis() - secondStartTime

                                                            if ( secondTimeElapsed in 4000..13000 && secondTimeElapsed-timeElapsed > 2000) {
                                                                api.organizer().sendToOrganizer(httpRequestResponse)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    arrayElement.isObject -> {
                                        // 递归处理数组中的对象
                                        launch(fuzzingDispatcher) { 
                                            sleepInjectJson(prefix, arrayElement as ObjectNode, mapper, api, request, time_2, time_3) 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        // 静态后缀不进行扫描
        fun isStatic(path: String): Boolean {
            val extensionIndex = path.lastIndexOf(".")
            if (extensionIndex > -1) {
                val extension = path.substring(extensionIndex + 1)
                val excludeExtensions = setOf(
                    "3g2", "3gp", "7z", "aac", "abw", "aif", "aifc", "aiff", "apk", "arc", "au", "avi", "azw",
                    "bat", "bin", "bmp", "bz", "bz2", "cmd", "cmx", "cod", "com", "csh", "css", "csv", "dll",
                    "doc", "docx", "ear", "eot", "epub", "exe", "flac", "flv", "gif", "gz", "ico", "ics", "ief",
                    "jar", "jfif", "jpe", "jpeg", "jpg", "less", "m3u", "mid", "midi", "mjs", "mkv", "mov",
                    "mp2", "mp3", "mp4", "mpa", "mpe", "mpeg", "mpg", "mpkg", "mpp", "mpv2", "odp", "ods", "odt",
                    "oga", "ogg", "ogv", "ogx", "otf", "pbm", "pdf", "pgm", "png", "pnm", "ppm", "ppt", "pptx",
                    "ra", "ram", "rar", "ras", "rgb", "rmi", "rtf", "scss", "sh", "snd", "svg", "swf", "tar",
                    "tif", "tiff", "ttf", "vsd", "war", "wav", "weba", "webm", "webp", "wmv", "woff", "woff2",
                    "xbm", "xls", "xlsx", "xpm", "xul", "xwd", "zip", "js", "map", "so", "iso"
                )
                return excludeExtensions.contains(extension)
            }
            return false
        }

        fun isCached(path: String): Boolean {
            // 检查缓存文件中是否存在该路径
            val cacheFile = File("/tmp/cached_paths.txt")
            if (!cacheFile.exists()) {
                // 如果缓存文件不存在，则创建一个新的并写入当前path
                cacheFile.createNewFile()
                cacheFile.appendText("$path\n")
                return false
            }
            return cacheFile.readLines().any { it == path }
        }


        // 使用协程异步发送HTTP请求
        suspend fun sendRequestAsync(api: MontoyaApi, request: HttpRequest): HttpRequestResponse {
            return withContext(fuzzingDispatcher) {
//                api.logging().logToOutput("Sending request on thread: ${Thread.currentThread().name}")
                api.http().sendRequest(request)
            }
        }
    }
}
