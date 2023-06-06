<?php

require_once "sanitize.php";



$Sanitizer = new tloberg\Sanitizer();


$string = " Example text stuff's.\n-499,00 kr\n§!\"#$&/()=?`Her er <p>den</p>\ vi/ktige meldingen: <a>(thomas@tloberg.net)</a> æØå!?§!#$%&/()=?`^*;:";
$number = " 342,3.4-200.01";
$number_good = "300";
$double_good = "300.99";
$year = "564688";
$year_good = "2009";
$phone = "91536548";
$email = "thomas@tloberg.net";
$url = "assfpasohf://ojaspofasfjasfs#sfofdop&?=asdasda";
$url_good = "https://tloberg.net";
$fileurl_good = "file://tloberg.net/test.pdf";
$timestamp = "2235255235235";
$timestamp_good = time();
$date = "time()";
$date_good = date("Y-m-d");
$datetime = "time()";
$datetime_good = date("Y-m-d H:i:s");
$timestamp_good = time();
 


$array = array($string, $string, $string, $string);

$array_filters = array($Sanitizer->FILTER_STRING());

$array_filters_withkeys = array(
    $Sanitizer->FILTER_STRING(),
    $Sanitizer->FILTER_STRING(),
    $Sanitizer->FILTER_STRING(),
);

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

$object_filters = array(
    "A" => $Sanitizer->FILTER_DOUBLE(),
    "D" => $Sanitizer->FILTER_STRING(),
);

$object_deep_filters = array(
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
        "A" => $Sanitizer->FILTER_FILENAME(),
        "B" => $Sanitizer->FILTER_STRING(),
        "C" => $Sanitizer->FILTER_STRING(),
    ),
);

// custom strip_tags filter
$object_filters_custom = array(
    "A" => $Sanitizer->FILTER_DOUBLE(),
    "D" => function($var) { return (string) strip_tags($var); },
);


$deep_object_test = array (
    'application_id'=> $number_good,
    'firstname' 	=> $string,
    'lastname' 		=> $string,
    'phone' 		=> $phone,
    'email' 		=> $email,
    'report' 		=> $string,
    'result' 		=> $string,
    'files' 		=> "[{\"name\":\"c://test-##$#/&%(32432423'!/pdf-test.pdf\",\"path\":\"https://User\wwd!#$%&/(s/assets/attachments/2022/aasflasf.pdf\"}]",
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
    'files3' 		=> null,
    'expences' 		=> "[{\"sum\":123456,\"expence\":\"Expence string\",\"desc\":\"Description string\"},{\"sum\":1234,\"expence\":\"Test\",\"desc\":\"Test2\"}]",
    'completed' 	=> "6.9.2022",
    'totalexpence' 	=> $number_good,
    'approve_terms' => $string,
    'remove_this'   => $string,
    'accepted'      => 'true',
    'test_array' => array(
        $string,
        $string,
        $string,
    ),
    'current_timestamp' => time(),
);

$deep_object_filter = array (
    'application_id'=> $Sanitizer->FILTER_INTEGER(),
    'firstname' 	=> $Sanitizer->FILTER_STRING(),
    'lastname' 		=> $Sanitizer->FILTER_STRING(),
    'phone' 		=> $Sanitizer->FILTER_INTEGER(),
    'email' 		=> $Sanitizer->FILTER_EMAIL(),
    'report' 		=> $Sanitizer->FILTER_STRING(),
    'result' 		=> $Sanitizer->FILTER_STRING(),
    'files' 		=> array(
        array(
             "name" => $Sanitizer->FILTER_FILENAME(),
             "path" => $Sanitizer->FILTER_FILEPATH(),
        ),
    ),
    'files3' 		=> array(
        array(
             "name" => $Sanitizer->FILTER_FILENAME(),
             "path" => $Sanitizer->FILTER_FILEPATH(),
        ),
    ),
    'files2' 		=> array(
        array(
            "title" => $Sanitizer->FILTER_FILENAME(),
            "name" => $Sanitizer->FILTER_FILENAME(),
            "path" => $Sanitizer->FILTER_FILEPATH(),
        ),
    ),
    'expences' 		=> array(
        array(
            "sum" 	  => $Sanitizer->FILTER_DOUBLE(),
            "expence" => $Sanitizer->FILTER_STRING(),
            "desc" 	  => $Sanitizer->FILTER_STRING(),
        ),
    ),
    'completed' 	=> $Sanitizer->FILTER_STRING(),
    'accepted'      => $Sanitizer->FILTER_BOOLEAN(),
    'totalexpence' 	=> $Sanitizer->FILTER_FLOAT($Sanitizer->ONLY_POSITIVE),
    'approve_terms' => $Sanitizer->FILTER_INTEGER($Sanitizer->ONLY_NEGATIVE),
    'test_array' 		=> array(
        $Sanitizer->FILTER_STRING(),
    ),
    'current_timestamp' => $Sanitizer->FILTER_TIMESTAMP()
);
$deep_object_require = array (
    'application_id'=> true,
    'firstname' 	=> true,
    'lastname' 		=> true,
    'phone' 		=> true,
    'email' 		=> true,
    'report' 		=> false,
    'result' 		=> false,
    'files' 		=> true,
    'files3' 		=> false,
    'files2' 		=> true,
    'expences' 		=> array(
        array(
            "sum" 	  => true,
            "expence" => true,
            "desc" 	  => true,
        ),
    ),
    'completed' 	=> false,
    'accepted'      => true,
    'totalexpence' 	=> true,
    'approve_terms' => true,
    'test_array' 		=> true,
    'current_timestamp' => true
);

$tiltak_posts = array (
    "Title" => "BUP",
    "Address1" => "",
    "Address2" => "",
    "Zipcode" => "",
    "City" => "",
    "Actions" => array (
        null,
        null,
        null,
        null,
        null,
        null,
    ),
    "ExcludeAges" => array (
        null,
        null,
        null,
        null,
    ),
    "ExcludeCategories" => array (
        null,
        null,
        null,
        null,
    ),
    "ExcludeKeywords" => array (
        null,
        null,
        null,
        null,
        null,
        null,
    ),
    "Display_Status" => "Public",
    "Resources" => array (
        "{\"title\":\"Link1\",\"url\":\"https://google.no\"}",
        "{\"title\":\"Link2\",\"url\":\"https://google.no/\"}"
    ),
    "Contact-Details" => array (
            "{\"title\":\"Company\",\"name\":\"\",\"phone\":\"11223344\",\"email\":\"\"}"
    ),
    "LeadText" => "\"String from formData\"",
    "Description" => "\"Textarea string from formData\"",
    "nonce" => "randomnonce",
    "action" => "update-service",
    "ID" => 4,
    "request_url" => "/wp-admin/admin.php?page=services&action=edit&id=4",
    "referral_url" => "https://localhost/wp-admin/admin.php?page=services"
);
$tiltak_filters = array (
    'ID'                    => $Sanitizer->FILTER_INTEGER(),
    'Display_Status'        => $Sanitizer->FILTER_STRING(),
    'Title'                 => $Sanitizer->FILTER_STRING(),
    'Address1'              => $Sanitizer->FILTER_STRING(),
    'Address2'              => $Sanitizer->FILTER_STRING(),
    'Zipcode'               => $Sanitizer->FILTER_INTEGER(),
    'City'                  => $Sanitizer->FILTER_STRING(),
    'LeadText' 	            => $Sanitizer->FILTER_STRING(),
    'Description'           => $Sanitizer->FILTER_STRING(),
    'ExcludeAges'           => array($Sanitizer->FILTER_INTEGER()),
    'ExcludeCategories'     => array($Sanitizer->FILTER_INTEGER()),
    'ExcludeKeywords'       => array($Sanitizer->FILTER_INTEGER()),
    'Actions'	            => array($Sanitizer->FILTER_INTEGER()),
    'Resources' 		    => array(
        array(
             "title"        => $Sanitizer->FILTER_STRING(),
             "url"          => $Sanitizer->FILTER_URL($Sanitizer->NO_VALIDATION),
        ),
    ),
    'Contact-Details' 		=> array(
        array(
             "title"        => $Sanitizer->FILTER_STRING(),
             "name"         => $Sanitizer->FILTER_STRING(),
             "phone"        => $Sanitizer->FILTER_STRING(),
             "email"        => $Sanitizer->FILTER_STRING(),
        ),
    ),
    'Contact-Details-URL'   => $Sanitizer->FILTER_URL($Sanitizer->NO_VALIDATION),
);
$tiltak_require = array (
    'ID'                    => false,
    'Display_Status'        => true,
    'Title'                 => true,
    'Address1'              => false,
    'Address2'              => false,
    'Zipcode'               => false,
    'City'                  => false,
    'LeadText' 	            => true,
    'Description'           => false,
    'ExcludeAges'           => false,
    'ExcludeCategories'     => false,
    'ExcludeKeywords'       => false,
    'Actions'	            => false,
    'Resources' 		    => false,
    'Contact-Details' 		=> false,
    'Contact-Details-URL'   => false,
);




/**
 * TESTS
 */

header("Content-Type: application/json");

// String
// echo json_encode(array("result" => $Sanitizer->Sanitize_Variable($string, $Sanitizer->FILTER_STRING())));

// Number
// echo json_encode(array(
//     "input"  => array(
//         "value" => $number,
//         "type" => gettype($number),
//     ),
//     "result" => array(
//         "value" => $Sanitizer->Sanitize_Variable($number, $Sanitizer->FILTER_DOUBLE()),
//         "type" => gettype($Sanitizer->Sanitize_Variable($number, $Sanitizer->FILTER_DOUBLE()))
//     ),
// ));

// String array
// echo json_encode($Sanitizer->Sanitize_Array($array, $Sanitizer->FILTER_STRING()));

// Array with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Array($array, $array_filters));

// Array with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Array($array, $array_filters_withkeys));

// Object with keys and filter for those keys
// echo json_encode($Sanitizer->Sanitize_Object((object) $object, (object) $object_filters));

// Object with keys and filter for those keys with custom filter
// echo json_encode($Sanitizer->Sanitize_Object((object) $object, (object) $object_filters_custom));

// Object with keys and filter for those keys with custom filter deep object
// echo json_encode($Sanitizer->Sanitize_Object((object) $object_deep, (object) $object_deep_filters));

// Deep object string sanitation
// echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $Sanitizer->FILTER_STRING()));

// Deep object string sanitation
// echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $deep_object_filter));
// echo json_encode($Sanitizer->Sanitize_Object((object) $deep_object_test, $deep_object_filter, $Sanitizer->EXPECT_JSON));

// $data = $Sanitizer->Sanitize_Object((object) $deep_object_test, $deep_object_filter, $Sanitizer->EXPECT_JSON);
// echo json_encode(array(
//     "all_fields_good" => $Sanitizer->CHECK_REQUIRED($data, $deep_object_require),
//     "data" => $data
// ));

$data = $Sanitizer->Sanitize_Object((object) $tiltak_posts, $tiltak_filters, $Sanitizer->EXPECT_JSON);
echo json_encode(array(
    "PassRequired" => $Sanitizer->CHECK_REQUIRED_ARRAY($data, $tiltak_require),
    "DATA" => $data,
    "POST" => $tiltak_posts,
));

?>
