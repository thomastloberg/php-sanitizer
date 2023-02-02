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
        "A" => $Sanitizer->FILTER_FILENAME($Sanitizer->DENY_NORWEGIAN),
        "B" => $Sanitizer->FILTER_STRING(),
        "C" => $Sanitizer->FILTER_STRING(),
    ),
);

// custom strip_tags filter
$object_filter_custom = array(
    "A" => $Sanitizer->FILTER_DOUBLE(),
    "D" => function($var) { return (string) strip_tags($var); },
);

$deep_object_test = array (
    'application_id'=> $number_good,
    'firstname' 	=> $string,
    'lastname' 		=> $string,
    'phone' 		=> $phone,
    'email' 		=> $email,
    'comment' 		=> $string,
    'files' 		=> array(
        array(
             "path" => $string,
             "name" => $string,
        ),
        array(
             "path" => $string,
             "name" => $string,
             "bad" => $string,
        ),
        array(
             "path" => $string,
             "name" => $string,
        ),
    ),
    'files2' 		=> array(
        array(
             "path" => $string,
             "name" => $string,
        ),
        array(
             "path" => $string,
             "name" => $string,
             "bad" => $string,
        ),
        array(
             "path" => $string,
             "name" => $string,
        ),
    ),
    'expences' 		=> array(
        array(
            "sum" 	  => $number_good,
            "expence" => $string,
            "desc" 	  => $string,
        ),
        array(
            "sum" 	  => $number_good,
            "expence" => $string,
            "desc" 	  => $string,
        ),
    ),
    'completed' 	=> $string,
    'totalexpence' 	=> $number_good,
    'approve_terms' => $string,
    'remove_this' => $string,
    'test_array' => array(
        $string,
        $string,
        $string,
    ),
);

$deep_object_filter = array (
    'application_id'=> $Sanitizer->FILTER_INTEGER(),
    'firstname' 	=> $Sanitizer->FILTER_STRING(),
    'lastname' 		=> $Sanitizer->FILTER_STRING(),
    'phone' 		=> $Sanitizer->FILTER_INTEGER(),
    'email' 		=> $Sanitizer->FILTER_EMAIL(),
    'comment' 		=> $Sanitizer->FILTER_STRING(),
    'files' 		=> array(
        array(
             "path" => $Sanitizer->FILTER_FILEPATH(),
             "name" => $Sanitizer->FILTER_FILENAME(),
        ),
    ),
    'files2' 		=> array(
        $Sanitizer->FILTER_STRING(),
    ),
    'expences' 		=> array(
        array(
            "sum" 	  => $Sanitizer->FILTER_DOUBLE(),
            "expence" => $Sanitizer->FILTER_STRING(),
            "desc" 	  => $Sanitizer->FILTER_STRING(),
        ),
    ),
    'completed' 	=> $Sanitizer->FILTER_STRING(),
    'totalexpence' 	=> $Sanitizer->FILTER_INTEGER(),
    'approve_terms' => $Sanitizer->FILTER_INTEGER(),
    'test_array' 		=> array(
        $Sanitizer->FILTER_STRING(),
    ),
);



/**
 * Examples
 */
header("Content-Type: application/json");

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

// Sanitize deep object string
// echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $Sanitizer->FILTER_STRING(), $Sanitizer->DEEP_ARRAY));

// Sanitize Deep object filter without deep with bug
// echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $deep_object_filter));

// Sanitize Deep object filter
echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $deep_object_filter, $Sanitizer->DEEP_ARRAY));

?>
