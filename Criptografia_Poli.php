<?php
$remote_addr = $_SERVER['REMOTE_ADDR'];
//verifica o IP que está enviando a informação
if($remote_addr != "IP") { 
    Logger(" CriptoPoli -- $remote_addr tried send information but was not the correct IP \n");
    http_response_code(400);
    exit;
}

$postTextDataRaw = $_POST["data"];
//trata a string inicial para a string com caracteres especiais
$postTextDatab = rawurldecode($postTextDataRaw);
//caso especial em que a string fica com o caractere de espaço, ' ', trocando para '+' 
//$postTextData=preg_replace("/ /","+",$postTextDatab);
//chama a função de desencriptação passando toda a informação e a chave secreta simétrica
$textDataDecrypted = fnDecrypt($postTextData, "criptografiapoli" );

//separa a informação agora desencriptada e aloca em variáveis locais cada uma das partes que compõem a string
$pieces = explode("|", $textDataDecrypted);
$username = trim($pieces[0]);
$email = trim($pieces[1]);
$postHash = trim($pieces[2]);

//gera uma chave md5 com base nas informações desencriptadas acima
  $md5String = "$username|$email";
  $md5Generate = md5($md5String);

//verificações lógicas e log de todas as possíveis ações
    if($md5Generate === $postHash){

        $data = array(
            "email"=>$email
        );

        if(!$user->bind($data)) {
            throw new Exception("Could not bind data. Error:" . $user->getError() . "\n");
            Logger(" nMl -- Could not bind data. Error: " . $user->getError());
            http_response_code(500);
            echo "500 - error data bind";
            exit;
        }
        if (!$user->save()) {
            throw new Exception("Could not save user. Error:" . $user->getError() . "\n");
            Logger(" nMail -- Could not save data. Error: " . $user->getError());
            http_response_code(500);
            echo "500 - error saving user";
            exit;
        }else{
            Logger(" nMl -- $username email changed with success \n");
            http_response_code(200);
            echo "200 - OK";
            exit;
        }
    }else
    {
        Logger(" nMl -- Invalid Hash recieved, $postHash ins't the hash that I calculated with $username.\n");
        http_response_code(400);
        echo "400 - hash error";
        exit;
    }
}
//funções de desencriptação e encriptação com base no algoritimo Rijndael 128
function fnDecrypt( $sValue, $sSecretKey )
{
    return rtrim(
        mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,$sSecretKey,base64_decode($sValue),MCRYPT_MODE_ECB,
				mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128,MCRYPT_MODE_ECB), 
                MCRYPT_RAND
            )
        ), "\x00..\x1F"
    );
}

function fnEncrypt($sValue, $sSecretKey)
{
    return rtrim(
        base64_encode(
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_128,
                $sSecretKey, $sValue, 
                MCRYPT_MODE_ECB, 
                mcrypt_create_iv(
                    mcrypt_get_iv_size(
                        MCRYPT_RIJNDAEL_128, 
                        MCRYPT_MODE_ECB
                    ), 
                    MCRYPT_RAND)
                )
            ), "\x00..\x1F"
        );
}
//função que realiza o Log
function Logger($str)
{
    // Get time of request
    if( ($time = $_SERVER['REQUEST_TIME']) == '') {
        $time = time();
    }
    // Get IP address
    if( $remote_addr == '') {
        $remote_addr = "REMOTE_ADDR_UNKNOWN";
    }
    // Format the date and time
    $date = date(" Y-m-d H:i:s ", $time);
    $f = fopen("MLog.log", "at");
    fwrite($f, "$date,$remote_addr,$str\n");
    @fclose($f);
}    
?>