<?php 
include "DB.php";
ob_start();
session_start();
error_reporting(E_ALL);
if (isset($_POST['submit-button'])) {
    $errors         = array();
    $nameSurname    = $_POST['nameSurname'];
    $email          = $_POST['email'];
    $password       = $_POST['password'];
    $re_password    = $_POST['re_password'];
    
    if (strlen($password) <= 5) {
        $errors[] = "Şifreniz minimum 5 karakterden oluşmaktadır.";
    }
    if ($password != $re_password) {
        $errors[] = "Şifreler Uyuşmamaktadır.";
    }
    if (!filter_var($email,FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Geçersiz Mail Adresi";
    }

    $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->bindValue(':email', $email);
    $stmt->execute();

    if ($stmt->fetchColumn() > 0) {
        $errors[] = "E-Posta Adresi Kullanılmaktadır.";
    }
    if (count($errors) == 0) {
        $encryptPassword = password_hash($password,PASSWORD_DEFAULT);
        $addUser = $db->prepare('INSERT INTO users (active ,name_surname, email, password,created_at) VALUES (0,:name_surname, :email, :password, :created_at)');
        $addUser->bindValue(':name_surname', $nameSurname, PDO::PARAM_STR);
        $addUser->bindValue(':email', $email, PDO::PARAM_STR);
        $addUser->bindValue(':password', $encryptPassword, PDO::PARAM_STR);
        $addUser->bindValue(':created_at', date("Y-m-d H:i:s"));
        $addUser->execute();

        if ($addUser) {
            $_SESSION['success'] = 1;
            header("location:/");
        }
    }
    else{
        $_SESSION['error'] = $errors;
        header("location:kayit");
    }
}
if (isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $loginUser = $db->prepare("SELECT * FROM users WHERE email = :email");
    $loginUser->bindValue(':email',$email,PDO::PARAM_STR);
    $loginUser->execute();
    $user = $loginUser->fetch(PDO::FETCH_ASSOC);

    
    if($user && password_verify($password, $user['password']) && $user['active'] == 1) {
        $_SESSION['admin'] = 1;
        header("location:anasayfa");
    }
    else {
        $_SESSION['login_failed'] = "Kullanıcı Adı veya Şifre Hatalı";
        header("location:/");
    }
}
