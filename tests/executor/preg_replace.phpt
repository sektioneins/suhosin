--TEST--
Testing protection against "\0" in preg_replace() first parameter
--SKIPIF--
<?php include "../skipif.inc"; ?>
--INI--
suhosin.log.sapi=0
--FILE--
<?php
    
    $text1 = "One little boy with two dogs, three cats and four birds";
    $text2 = "The three cats eat the four birds";

    $regex_array = array("/one/", "/two/", "/three/");
    $regex_array0 = array("/one/\0", "/two/", "/three/");
    $replace_array = array("1", "2", "3");
    $regex = "/eat/";
    $regex0 = "/ea\0t/";
    $replace = "play with";
    
    var_dump(preg_replace($regex_array, $replace_array, $text1));
    var_dump(preg_replace($regex_array0, $replace_array, $text1));
    var_dump(preg_replace($regex, $replace, $text2));
    var_dump(preg_replace($regex0, $replace, $text2));
    
?>
--EXPECT--
string(49) "One little boy with 2 dogs, 3 cats and four birds"
bool(false)
string(39) "The three cats play with the four birds"
bool(false)
