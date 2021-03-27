<?php
    // curl --header "Content-Type: application/json" --request POST  --data '{"value":"313375"}' http://your_server_ip/index.php
    // $otp_token = strval(mt_rand(000000, 999999));
    // echo $otp_token;
    echo "Test Server. Don't waste your time.\n";
    $otp_token = "000011"; // Test token
    if($_SERVER['REQUEST_METHOD'] === 'POST') {
        $json = file_get_contents('php://input');
        $data = json_decode($json);
        try {
            $user_otp = $data->value;
        } catch (Exception $e){
            die();
        }
    } else {
        die();
    }

    if ($user_otp === $otp_token) {
        setcookie('test_server', 'otp_has_been_found');
        $data = "null";
    } else {
        $data = '{"detail": {"exception": "InvalidOTPValueError", "message": "Invalid 2FA value"}}';
    }
    header('Content-Type: application/json');
    echo json_encode($data);    
?>
