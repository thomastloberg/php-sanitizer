<?php

require_once "sanitize.php";

 /*
 * The Sanitizer class
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
 * TESTS
 */

// Return tests as json data
header("Content-Type: application/json");


// String
// echo json_encode(array("result" => $Sanitizer->Sanitize_Variable($string, $Sanitizer->FILTER_STRING())));

// Number
echo json_encode(array(
    "input"  => array(
        "value" => $number,
        "type" => gettype($number),
    ),
    "result" => array(
        "value" => $Sanitizer->Sanitize_Variable($number, $Sanitizer->FILTER_DOUBLE()),
        "type" => gettype($Sanitizer->Sanitize_Variable($number, $Sanitizer->FILTER_DOUBLE()))
    ),
));

// String array
// echo json_encode($Sanitizer->Sanitize_Array($array, $Sanitizer->FILTER_STRING()));

// Array with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Array($array, $array_filter));

// Array with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Array($object, $object_filter));

// Object with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Object((object) $object, (object) $object_filter));

// Object with keys and filter for those keys with custom filter
// echo json_encode($Sanitizer->Sanitize_Object((object) $object, (object) $object_filter_custom));

// Object with keys and filter for those keys with custom filter deep object
// echo json_encode($Sanitizer->Sanitize_Object((object) $object_deep, (object) $object_deep_filter));

?>
