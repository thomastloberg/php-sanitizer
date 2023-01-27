<?php

require_once "sanitize.php";

 /*
 * Initialize the Sanitizer class
 */
$Sanitizer = new tloberg\Sanitizer();



/*
 * Some bad input
 */
$string = " Example text stuff's.\n-499,00 kr\n§!\"#$&/()=?`Her er <p>den</p>\ vi/ktige meldingen: <a>(thomas@tloberg.net)</a> æØå!?§!#$%&/()=?`^*;:";
$number = " 342,3.4-200.01";
$array = array($string, $string, $string, $string);
$object = array(
    "A" => $string,
    "B" => $string,
    "C" => $string,
);
$object_deep = array(
    "D" => $object,
    "E" => $object,
    "F" => $object,
);



/*
 *  Example filters
 */

// Array
$array_filter = array(
    0 => $Sanitizer->FILTER_STRING(),
    1 => $Sanitizer->FILTER_STRING(),
);

$object_filter = array(
    "A" => $Sanitizer->FILTER_DOUBLE(),
    "D" => $Sanitizer->FILTER_STRING(),
);

$object_deep_filter = array(
    "D" => array(
        // In FILTER_STRING() you can pass flags
        "A" => $Sanitizer->FILTER_STRING(array(
            $Sanitizer->ALLOW_QUOTES, 
            $Sanitizer->NO_TRIM, 
            $Sanitizer->NO_HTMLSTRIP
        )),
        "C" => $Sanitizer->FILTER_STRING(),
    ),
    "F" => array(
        "A" => $Sanitizer->FILTER_FILENAME($Sanitizer->ALLOW_NORWEGIAN),
        "B" => $Sanitizer->FILTER_STRING(),
        "C" => $Sanitizer->FILTER_STRING(),
    ),
);

// custom strip_tags filter
$object_filter_custom = array(
    "A" => $Sanitizer->FILTER_DOUBLE(),
    "D" => function($var) { return (string) strip_tags($var); },
);



/**
 * Examples
 */

// Sanitize String
// echo $Sanitizer->Sanitize_Variable($string, $Sanitizer->FILTER_STRING());

// Sanitize Double
// echo $Sanitizer->Sanitize_Variable($number, $Sanitizer->FILTER_DOUBLE());

// Sanitize String Array
// echo $Sanitizer->Sanitize_Array($array, $Sanitizer->FILTER_STRING());

// Sanitize Array
// echo $Sanitizer->Sanitize_Array($array, $array_filter);

// Sanitize Object
// echo $Sanitizer->Sanitize_Object((object) $object, (object) $object_filter);

// Sanitize Object with Custom Filter
// echo $Sanitizer->Sanitize_Object((object) $object, (object) $object_filter_custom);

// Sanitize Objects inside Objects
// echo $Sanitizer->Sanitize_Object((object) $object_deep, (object) $object_deep_filter);

?>
