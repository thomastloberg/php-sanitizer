<?php

/**
 * 
 *                 PHP Sanitizer
 * 
 * 
 * @version 1.2.71
 * @author Thomas Tufta Løberg
 * @link https://github.com/thomastloberg/php-sanitizer
 * @license https://github.com/thomastloberg/php-sanitizer/LICENSE
 * 
 * 
 * 
 * If you want to trust the data and make sure
 * an object or array have the keys you
 * need without manually checking each one.
 * 
 * After sanitizing variable it will get passed
 * through a validation proces and return 
 * INVALID_DATA() if no data / invalid
 * INVALID_DATA Default answer: empty array or null
 * 
 * 
 * 
 * Supported formats:
 *      Raw             # No sanitize
 *      Array           # Filter Array  = Output Array.  (optional flags: DEEP_ARRAY, EXPECT_JSON)
 *      Object          # Filter Object = Output Object. (optional flags: DEEP_ARRAY, EXPECT_JSON)
 *      Double          # Sanitize Double    (optional flags: NO_VALIDATION, STRICT, ONLY_POSITIVE, ONLY_NEGATIVE)
 *      Float           # Sanitize Float     (optional flags: NO_VALIDATION, STRICT, ONLY_POSITIVE, ONLY_NEGATIVE)
 *      Integer         # Sanitize Integer   (optional flags: NO_VALIDATION, STRICT, ONLY_POSITIVE, ONLY_NEGATIVE)
 *      Boolean         # Sanitize Boolean
 *      String          # Sanitize String    (optional flags: DENY_NORWEGIAN, NO_TRIM, NO_HTMLSTRIP, ALLOW_QUOTES)
 *      String Custom   # Sanitize String w/ Custom Allowed Chars
 *      Filename        # Sanitize Filename  (optional flags: DENY_NORWEGIAN)
 *      Filepath        # Sanitize Filepath  (optional flags: DENY_NORWEGIAN)
 *      URL             # Sanitize URL       (optional flags: NO_VALIDATION)
 *      Email           # Sanitize Email     (optional flags: NO_VALIDATION)
 *      Year            # Sanitize Year      (optional flags: NO_VALIDATION)
 *      Timestamp       # Sanitize timestamp (optional flags: NO_VALIDATION)
 *      Date            # Sanitize Date      (optional flags: NO_VALIDATION)
 *      DateTime        # Sanitize DateTime  (optional flags: NO_VALIDATION)
 *      Custom String   # Sanitize String w/ Only Allowed Chars (optional flags: DENY_NORWEGIAN, NO_TRIM, NO_HTMLSTRIP, ALLOW_QUOTES)
 *      Remove Chars    # Remove Custom Chars from String
 *      Custom          # Use your custom sanitizing function
 * 
 * 
 * Validation formats:
 *      Integer             # All numbers (double, float, integer) accepted
 *      Integer (strict)    # ONLY integer
 *      Double              # All numbers (double, float, integer) accepted
 *      Double (strict)     # ONLY double
 *      Float               # All numbers (double, float, integer) accepted
 *      Float (strict)      # ONLY float
 *      URL
 *      Email
 *      Year
 *      Timestamp
 *      Date
 *      Datetime
 *      JSON
 * 
 * 
 * Check Required:
 *      MISSING_FIELDS()  # False if no missing fields, Array of fields if missing
 * 
 * 
 */

namespace tloberg;


class Sanitizer {
    /**
     * FLAGS
     */
    public $ALLOW_QUOTES   = "ALLOW_QUOTES";        // Allow single and double quotes in string
    public $NO_TRIM        = "NO_TRIM";             // Allow white-space at ends in string
    public $NO_HTMLSTRIP   = "NO_HTMLSTRIP";        // Allow HTML tags in string
    public $DENY_NORWEGIAN = "DENY_NORWEGIAN";      // Deny norwegian letters
    public $STRICT         = "STRICT";              // Strict Integer - Double and Float numbers will result in INVALID_DATA
    public $NO_VALIDATION  = "NO_VALIDATION";       // Prevent default validation on: Double, Float, Integer, Email, Date, Datetime
    public $DEEP_ARRAY     = "DEEP_ARRAY";          // Sanitize_Array and Sanitize_Object flag where simple filter will filter ALL array keys and object properties
    public $EXPECT_JSON    = "EXPECT_JSON";         // Look for and decode JSON if found before continue
    public $ONLY_POSITIVE  = "ONLY_POSITIVE";       // Only accept positive number in: Integer, Float or Double
    public $ONLY_NEGATIVE  = "ONLY_NEGATIVE";       // Only accept negative number in: Integer, Float or Double

    
    public function __construct             () {}


    /* 
     * MAIN
     */
    public function Sanitize_Variable       ($var, $filter, $flags=null) {
        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // error prevention: if function passed into input array
        if (!is_callable($filter)) {
            return $this->INVALID_DATA(null, "Function");
        }

        // look for JSON data and decode if found
        if (in_array($this->EXPECT_JSON, $flags)) {
            if ($this->VALIDATE_JSON($var)) {
                // if json then decode
                $var = json_decode($var);
            } else if (is_string($var) && $this->VALIDATE_JSON(stripslashes($var))) {
                // if formdata added slashes -> remove and decode
                $var = json_decode(stripslashes($var));
            }
        }

        if (is_object($var)) $var = (array) $var;

        return count($flags) > 0 ? $filter($var, $flags) : $filter($var);
    }
    public function Sanitize_Array          ($arr, $filter, $flags=null) {
        $return_array = array();

        // error prevention: if function passed into input array
        if (is_callable($arr))    return $this->INVALID_DATA(null, "Function");
        if (is_callable($filter)) $filter = array($filter);

        // correct data
        if (is_object($arr))    $arr    = (array) $arr;
        if (is_object($filter)) $filter = (array) $filter;

        // error prevention: convert to array if isn't
        if (!is_array($arr))    $arr    = array($arr);
        if (!is_array($flags))  $flags  = array($flags);
        if (!is_array($filter)) $filter = array($filter);


        if(count($filter) == 1 && empty(array_keys($filter)[0])) {

            // Expected array with one filter
            return $this->FUNCTION_SANITIZE_ARRAY_SINGLEKEY($return_array, $arr, $filter, $flags);

        } else {

            // Expected array with multiple filters
            return $this->FUNCTION_SANITIZE_ARRAY_MULTIPLEKEYS($return_array, $arr, $filter, $flags);

        }
    }
    public function Sanitize_Object         ($obj, $filter, $flags=null) {
        if (is_object($obj)) { $obj = (array) $obj; }
        if (is_object($filter)) { $filter = (array) $filter; }

        return (object) $this->Sanitize_Array($obj, $filter, $flags);
    }
    public function MISSING_FIELDS          ($arr, $required_fields, $flags=null) {
        // Another name for VALIDATE_REQUIRED_FIELDS to make it more readable
        $validate = $this->VALIDATE_REQUIRED_FIELDS($arr, $required_fields, $flags);
        return $validate === true ? false : $validate;
    }


    /**
     * FILTERS
     */
    public function FILTER_RAW              ($flags=null) {
        return function($var) use ($flags) { 
            return $this->FUNCTION_FILTER_RAW($var, $flags);
        };
    }
    public function FILTER_BOOLEAN          ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_BOOLEAN($var, $flags);
        };
    }
    public function FILTER_INTEGER          ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_INTEGER($var, $flags);
        };
    }
    public function FILTER_DOUBLE           ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DOUBLE($var, $flags);
        };
    }
    public function FILTER_FLOAT            ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FLOAT($var, $flags);
        };
    }
    public function FILTER_STRING           ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_STRING($var, $flags);
        };
    }
    public function FILTER_STRING_CUSTOM    ($allowCustom, $flags=null) {
        return function($var) use ($allowCustom, $flags) {
            return $this->FUNCTION_FILTER_STRING_ALLOW_CUSTOM($var, $allowCustom, $flags);
        };
    }
    public function REMOVE_CHARS            ($denyCustom, $flags=null) {
        return function($var) use ($denyCustom, $flags) {
            return $this->FUNCTION_FILTER_STRING_DENY_CUSTOM($var, $denyCustom, $flags);
        };
    }
    public function FILTER_FILENAME         ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FILENAME($var, $flags);
        };
    }
    public function FILTER_FILEPATH         ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FILEPATH($var, $flags);
        };
    }
    public function FILTER_URL              ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_URL($var, $flags);
        };
    }
    public function FILTER_EMAIL            ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_EMAIL($var, $flags);
        };
    }
    public function FILTER_YEAR             ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_INTEGER($var, $flags);
        };
    }
    public function FILTER_TIMESTAMP        ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_TIMESTAMP($var, $flags);
        };
    }
    public function FILTER_DATE             ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DATE($var, $flags);
        };
    }
    public function FILTER_DATETIME         ($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DATETIME($var, $flags);
        };
    }


    /**
     * VALIDATION
     */
    public function VALIDATE_INTEGER           ($var): bool {
        return is_numeric($var);
    }
    public function VALIDATE_INTEGER_STRICT    ($var): bool {
        return (is_numeric($var) && !is_float($var) && !is_double($var));
    }
    public function VALIDATE_POSITIVE_INTEGER  ($var): bool {
        return is_numeric($var) && $var >= 0;
    }
    public function VALIDATE_NEGATIVE_INTEGER  ($var): bool {
        return is_numeric($var) && $var < 0;
    }
    public function VALIDATE_DOUBLE            ($var): bool {
        return (is_numeric($var) || is_double($var) || is_float($var));
    }
    public function VALIDATE_DOUBLE_STRICT     ($var): bool {
        return (is_numeric($var) && is_double($var) && !is_float($var));
    }
    public function VALIDATE_FLOAT             ($var): bool {
        return (is_numeric($var) || is_float($var) || is_double($var));
    }
    public function VALIDATE_FLOAT_STRICT      ($var): bool {
        return (is_numeric($var) && is_float($var) && !is_double($var));
    }
    public function VALIDATE_URL               ($var): bool {
        return filter_var($var, FILTER_VALIDATE_URL);
    }
    public function VALIDATE_EMAIL             ($var): bool {
        return filter_var($var, FILTER_VALIDATE_EMAIL);
    }
    public function VALIDATE_YEAR              ($var): bool {
        return (is_numeric($var) && strlen($var) === 4);
    }
    public function VALIDATE_TIMESTAMP         ($var): bool {
        return (ctype_digit($var) && strtotime(date('Y-m-d H:i:s', $var)) === (int)$var);
    }
    public function VALIDATE_DATE              ($var): bool {
        // YYYY-MM-DD
        return preg_match("/^[0-9]{4}[\\|\/|\.|\-][0-9]{1,2}[\\|\/|\.|\-][0-9]{1,2}$/", $var);
    }
    public function VALIDATE_DATETIME          ($var): bool {
        // YYYY-MM-DD HH:MM:SS
        return preg_match("/^[0-9]{4}[\\|\/|\.|\-][0-9]{1,2}[\\|\/|\.|\-][0-9]{1,2}\s[0-9]{1,2}[\.|\-|\:][0-9]{1,2}[\.|\-|\:][0-9]{1,2}$/", $var);
    }
    public function VALIDATE_JSON              ($var): bool {
        // not string == not JSON
        if (!is_string($var)) {
            return false;
        }

        // try to decode
        json_decode($var);

        // if no json error then successfull json
        return json_last_error() === JSON_ERROR_NONE;
    }
    public function VALIDATE_REQUIRED_FIELDS   ($arr, $required_array, $flags=null) {
        // error prevention: if function passed into input array
        if (is_callable($arr))              return false;
        if (is_callable($required_array))   $required_array = array($required_array);

        // correct data
        if (is_object($arr))            $arr = (array) $arr;
        if (is_object($required_array)) $required_array = (array) $required_array;

        // error prevention: convert to array if isn't
        if (!is_array($arr))            $arr = array($arr);
        if (!is_array($flags))          $flags = array($flags);
        if (!is_array($required_array)) $required_array = array($required_array);


        if(count($required_array) == 1 && empty(array_keys($required_array)[0])) {

            // Expected array with one filter
            return $this->VALIDATE_REQUIRED_FIELDS_SINGLEKEY($arr, $required_array, $flags);

        } else {

            // Expected array with multiple filters
            return $this->VALIDATE_REQUIRED_FIELDS_MULTIPLEKEYS($arr, $required_array, $flags);

        }
    }




    /**
     * DEPENDENCY FUNCTIONS
     */


    /* Helper Return Values */
    public function INVALID_DATA            ($expected_datatype=null, $received_datetype=null) {
        /**
         * Default: return null if invalid data (no data or wrong type)
         */

        // DEFAULT_EMPTY_VALUE() is REQUIRED to give $this->CHECK_REQUIRED() the correct datatype
        // Comment DEFAULT_EMPTY_VALUE() if you want more detailed response on INVALID DATA
        return $this->DEFAULT_EMPTY_VALUE($expected_datatype);


        /**
         * Optional: return Invalid {type} or No data
         */
        $return_text = "";

        if (empty($expected_datatype)) {

            if (empty($received_datetype)) {
                return "No data";
            } else {
                return "Invalid (" . ucwords(strtolower($received_datetype)) . ")";
            }

        } else {

            $return_text = "Invalid. Expected: " .$expected_datatype;

            if (!empty($received_datetype))
                $return_text .= " (" . ucwords(strtolower($received_datetype)) . ")";

            return $return_text;
        }

    }
    public function DEFAULT_EMPTY_VALUE       ($datatype=null) {
        /**
         * If variable is empty then return default value
         */

        if(!is_null($datatype) && strtolower($datatype) == "array") {
            return array();
        // } else if($datatype != null && strtolower($datatype) == "boolean") {
        //     return false;
        } else {
            return null;
        }
    }
    public function RETURN_IF_NOT_EMPTY       ($var, $datatype=null) {
        if (is_string($var) || is_integer($var) || is_double($var) || is_float($var)) {
            if (is_null($var) || strlen($var) === 0) {
                if (empty($datatype)) {
                    return $this->INVALID_DATA(gettype($var));
                } else {
                    return $this->INVALID_DATA($datatype);
                }
            }

            return $var;
        }

        if (empty($var)) {
            if (empty($datatype)) {
                return $this->INVALID_DATA(gettype($var));
            } else {
                return $this->INVALID_DATA($datatype);
            }
        }

        return $var;
    }
    public function RETURN_ONLY_ALLOWED_CHARS ($var, $allowedChars): string {
        if(strlen($var) == 0) return "";

        $output = "";

        $allowedChars = str_replace("0-9", "0123456789", $allowedChars);
        $allowedChars = str_replace("a-z", "abcdefghijklmnopqrstuvwxyz", $allowedChars);
        $allowedChars = str_replace("A-Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", $allowedChars);
        $allowedChars = str_replace("a-Z", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", $allowedChars);

        $accepted_chars_arr = str_split($allowedChars);

        foreach(str_split($var) as $char){
            if(in_array($char, $accepted_chars_arr)) $output .= $char;
        }

        return $output;
    }
    public function RETURN_ALL_EXCEPT_CHARS   ($var, $deniedChars): string {
        if(strlen($var) == 0) return "";

        $output = "";

        $deniedChars = str_replace("0-9", "0123456789", $deniedChars);
        $deniedChars = str_replace("a-z", "abcdefghijklmnopqrstuvwxyz", $deniedChars);
        $deniedChars = str_replace("A-Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", $deniedChars);
        $deniedChars = str_replace("a-Z", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", $deniedChars);

        $denied_chars_arr = str_split($deniedChars);

        foreach(str_split($var) as $char){
            if(!in_array($char, $denied_chars_arr)) $output .= $char;
        }

        return $output;
    }

    /* Filter / Sanitizing Functions */
    public function FUNCTION_FILTER_RAW     ($var, $flags=null) {
        // error prevention: turn flags into array
        if (!is_array($flags)) { $flags = array($flags); }

        return $var;
    }
    public function FUNCTION_FILTER_BOOLEAN ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Boolean"); }

        // error prevention: turn flags into array
        if (!is_array($flags)) { $flags = array($flags); }

        // quick check with simple convertion if true or false
        if ($var === TRUE) return true;
        if ($var === 0 || $var === '0') return false;

        // sanitize boolean. Returns: True / False / null
        $var = filter_var($var, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if ($var === null) {
            return $this->INVALID_DATA("Boolean");
        } else {
            return $this->RETURN_IF_NOT_EMPTY((boolean) $var);
        }
    }
    public function FUNCTION_FILTER_INTEGER ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Integer"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // sanitize variable
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, "0-9-");


        /**
         * Flags
         */

        // return without validation
        if (in_array($this->NO_VALIDATION, $flags))
            return $this->RETURN_IF_NOT_EMPTY((integer) $var);

        // return INVALID_DATA if not positive number
        if (in_array($this->ONLY_POSITIVE, $flags))
            if (!$this->VALIDATE_POSITIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return INVALID_DATA if not negative number
        if (in_array($this->ONLY_NEGATIVE, $flags))
            if (!$this->VALIDATE_NEGATIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return null if no valid integer
        if (in_array($this->STRICT, $flags)) {

            // Valid
            if ($this->VALIDATE_INTEGER_STRICT($var)) return $this->RETURN_IF_NOT_EMPTY((integer) $var);
            
            // Invalid
            return $this->INVALID_DATA("Integer");

        }

        // Valid
        if ($this->VALIDATE_INTEGER($var)) return $this->RETURN_IF_NOT_EMPTY((integer) $var);

        // Invalid
        return $this->INVALID_DATA("Integer");
    }
    public function FUNCTION_FILTER_DOUBLE  ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Double"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // sanitize variable
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, "0-9.,-");


        /**
         * Flags
         */

        // return without validation
        if (in_array($this->NO_VALIDATION, $flags))
            return $this->RETURN_IF_NOT_EMPTY((double) $var);

        // return INVALID_DATA if not positive number
        if (in_array($this->ONLY_POSITIVE, $flags))
            if (!$this->VALIDATE_POSITIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return INVALID_DATA if not negative number
        if (in_array($this->ONLY_NEGATIVE, $flags))
            if (!$this->VALIDATE_NEGATIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return null if no valid integer
        if (in_array($this->STRICT, $flags)) {

            // Valid
            if ($this->VALIDATE_DOUBLE_STRICT($var)) return $this->RETURN_IF_NOT_EMPTY((double) $var);
            
            // Invalid
            return $this->INVALID_DATA("Double");

        }

        // Valid
        if ($this->VALIDATE_DOUBLE($var)) return $this->RETURN_IF_NOT_EMPTY((double) $var);
            
        // Invalid
        return $this->INVALID_DATA("Double");
    }
    public function FUNCTION_FILTER_FLOAT   ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Float"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // sanitize variable
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, "0-9.,-");


        /**
         * Flags
         */

        // return without validation
        if (in_array($this->NO_VALIDATION, $flags))
            return $this->RETURN_IF_NOT_EMPTY((float) $var);

        // return INVALID_DATA if not positive number
        if (in_array($this->ONLY_POSITIVE, $flags))
            if (!$this->VALIDATE_POSITIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return INVALID_DATA if not negative number
        if (in_array($this->ONLY_NEGATIVE, $flags))
            if (!$this->VALIDATE_NEGATIVE_INTEGER($var)) return $this->INVALID_DATA("Integer");

        // return null if no valid integer
        if (in_array($this->STRICT, $flags)) {

            // Valid
            if ($this->VALIDATE_FLOAT_STRICT($var)) return $this->RETURN_IF_NOT_EMPTY((float) $var);
                
            // Invalid
            return $this->INVALID_DATA("Float");

        }
        
        // Valid
        if ($this->VALIDATE_FLOAT($var)) return $this->RETURN_IF_NOT_EMPTY((float) $var);
            
        // Invalid
        return $this->INVALID_DATA("Float");
    }
    public function FUNCTION_FILTER_STRING  ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("String"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        
        // Remove everything except these characters:
        $accepted_chars  = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,.:;_-+=\/€$§|*[]!?@#%&()';
        $accepted_chars .= "\t\r\n"; // Tabs, Newline and Carriage Return
        $accepted_chars .= chr(32);  // Regular Space char


        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

        // if ALLOW_QUOTES flag present then add flag
        if (in_array($this->ALLOW_QUOTES, $flags)) $accepted_chars .= "\"'";

		// remove outer white-space - only if NO_TRIM flag isn't present
        if (!in_array($this->NO_TRIM, $flags)) $var = trim($var);

        // Default: Remove html tags, example: <p></p> - only if NO_HTMLSTRIP flag isn't present
        if (!in_array($this->NO_HTMLSTRIP, $flags)) $var = strip_tags($var);

        // NO_HTMLSTRIP then add < and > to allowed chars
        if (in_array($this->NO_HTMLSTRIP, $flags))  $accepted_chars .= "<>";


        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        return $this->RETURN_IF_NOT_EMPTY((string) $var);
    }
    public function FUNCTION_FILTER_STRING_ALLOW_CUSTOM  ($var, $allowCustom, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("String"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        
        // Remove everything except these characters
        $accepted_chars  = $allowCustom;

        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

        // if ALLOW_QUOTES flag present then add flag
        if (in_array($this->ALLOW_QUOTES, $flags)) $accepted_chars .= "\"'";

		// remove outer white-space - only if NO_TRIM flag isn't present
        if (!in_array($this->NO_TRIM, $flags)) $var = trim($var);

        // Default: Remove html tags, example: <p></p> - only if NO_HTMLSTRIP flag isn't present
        if (!in_array($this->NO_HTMLSTRIP, $flags)) $var = strip_tags($var);

        // NO_HTMLSTRIP then add < and > to allowed chars
        if (in_array($this->NO_HTMLSTRIP, $flags))  $accepted_chars .= "<>";


        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        return $this->RETURN_IF_NOT_EMPTY((string) $var);
    }
    public function FUNCTION_FILTER_STRING_DENY_CUSTOM   ($var, $denyCustom, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("String"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ALL_EXCEPT_CHARS($var, $denyCustom);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        return $this->RETURN_IF_NOT_EMPTY((string) $var);
    }
    public function FUNCTION_FILTER_FILENAME($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Filename"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // Remove everything except these characters:
        $accepted_chars  = 'a-zA-Z0-9_-.';
        $accepted_chars .= chr(32);  // Regular Space char


        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

		// remove outer white-space
        $var = trim($var);

        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        return $this->RETURN_IF_NOT_EMPTY((string) $var, "Filename");
    }
    public function FUNCTION_FILTER_FILEPATH($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Filepath"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // Remove everything except these characters:
        $accepted_chars  = 'a-zA-Z0-9_-.\/:';
        $accepted_chars .= chr(32);  // Regular Space char


        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

		// remove outer white-space
        $var = trim($var);

        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        return $this->RETURN_IF_NOT_EMPTY((string) $var, "Filepath");
    }
    public function FUNCTION_FILTER_URL     ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("URL"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // Remove Accent characters
        $var = $this->REPLACE_ACCENTS($var);

        // Remove Non-printable characters
        $var = $this->REPLACE_NONPRINTABLE($var);

        // sanitize url
        $var = filter_var($var, FILTER_SANITIZE_URL);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');


        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "URL");
        }

        // return url if validated true
        if ($this->VALIDATE_URL($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "URL");
        }

        return $this->INVALID_DATA("URL");
    }
    public function FUNCTION_FILTER_EMAIL   ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Email"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // Remove Accent characters
        $var = $this->REPLACE_ACCENTS($var);

        // Remove Non-printable characters
        $var = $this->REPLACE_NONPRINTABLE($var);

        // sanitize email
        $var = filter_var($var, FILTER_SANITIZE_EMAIL);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Email");
        }

        // return variable if valid Email address
        if ($this->VALIDATE_EMAIL($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Email");
        } else {
            return $this->INVALID_DATA("Email");
        }
    }
    public function FUNCTION_FILTER_YEAR    ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Year"); }
        
        // error prevention: turn flags into array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // sanitize year
        $var = (integer) filter_var($var, FILTER_SANITIZE_NUMBER_INT);

        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags))
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Year");

        if ($this->VALIDATE_YEAR($var))
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Year");

        return $this->INVALID_DATA("Year");
    }
    public function FUNCTION_FILTER_TIMESTAMP($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Timestamp"); }

        // error prevention: turn flags into array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // sanitize timestmp
        $var = (integer) filter_var($var, FILTER_SANITIZE_NUMBER_INT);

        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags))
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Timestamp");

        if ($this->VALIDATE_TIMESTAMP($var))
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Timestamp");


        return $this->INVALID_DATA("Timestamp");
    }
    public function FUNCTION_FILTER_DATE    ($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Date"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // Remove everything except these characters:
        $accepted_chars  = '0-9_-.\/:';
        $accepted_chars .= chr(32);  // Regular Space char


        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

        // remove outer white-space
        $var = trim($var);

        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');
        

        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Date");
        }

        // return variable if valid Email address
        if ($this->VALIDATE_DATE($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Date");
        } else {
            return $this->INVALID_DATA("Date");
        }
    }
    public function FUNCTION_FILTER_DATETIME($var, $flags=null) {
        // error prevention: if $var is string then return null
        if ($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("DateTime"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if (!is_array($flags)) { $flags = array($flags); }

        // make sure input is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');

        // Remove everything except these characters:
        $accepted_chars  = '0-9_-.\/:';
        $accepted_chars .= chr(32);  // Regular Space char


        // if DENY_NORWEGIAN flag not present then add flag
        if (!in_array($this->DENY_NORWEGIAN, $flags)) $accepted_chars .= "æøåÆØÅ";

        // remove outer white-space
        $var = trim($var);

        // Remove all chars not in $accepted_chars
        $var = $this->RETURN_ONLY_ALLOWED_CHARS($var, $accepted_chars);

        // make sure output is UTF-8
        $var = mb_convert_encoding($var, 'UTF-8');
        

        // if NO_VALIDATION flag present then return without validation
        if (in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "DateTime");
        }

        // return variable if valid Email address
        if ($this->VALIDATE_DATETIME($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "DateTime");
        } else {
            return $this->INVALID_DATA("DateTime");
        }
    }

    /* Helper Functions */
    public function FUNCTION_SANITIZE_ARRAY_SINGLEKEY       ($return_array, $arr, $filter, $flags) {
        // error prevention: convert to array if isn't
        if (!is_array($flags))  $flags = array($flags);
        if (!is_array($arr))    return $this->INVALID_DATA("Array", gettype($arr));
        if (!is_array($filter)) return $this->INVALID_DATA("Array", gettype($filter));

        // foreach $arr
        foreach ($arr as $arrvalue) {
            // no value / nothing to validate
            if (!isset($arrvalue)) {
                $newValue = $this->INVALID_DATA();
                if ($newValue !== null) $return_array[] = $newValue;
                continue;
            }
            
            // look for JSON data and decode if found
            if (in_array($this->EXPECT_JSON, $flags)) {
                if ($this->VALIDATE_JSON($arrvalue)) {
                    // if json then decode
                    $arrvalue = json_decode($arrvalue);

                } else if (is_string($arrvalue) && $this->VALIDATE_JSON(stripslashes($arrvalue))) {
                    // if formdata added slashes -> remove and decode
                    $arrvalue = json_decode(stripslashes($arrvalue));
                }
            }
            
            // error prevention
            if (is_object($arrvalue)) $arrvalue = (array) $arrvalue;


            if (is_array($filter[0])) {
                $newValue = $this->Sanitize_Array($arrvalue, $filter[0], $flags);
                if ($newValue !== null) $return_array[] = $newValue;
                continue;
            }

            $newValue = $this->Sanitize_Variable($arrvalue, $filter[0], $flags);
            if ($newValue !== null) $return_array[] = $newValue;
        }

        // Validate that one or more keys have a value
        if(count($return_array) > 0) {
            foreach ($return_array as $returnvalue) {
                if (is_array($returnvalue) && count($returnvalue) > 0)
                    return $return_array;

                if ($returnvalue !== null)
                    return $return_array;
            }
        }

        // No value found
        return $this->INVALID_DATA("Array");
    }
    public function FUNCTION_SANITIZE_ARRAY_MULTIPLEKEYS    ($return_array, $arr, $filter, $flags) {
        // error prevention: convert to array if isn't
        if (!is_array($flags))  $flags = array($flags);
        if (!is_array($arr))    return $this->INVALID_DATA("Array", gettype($arr));
        if (!is_array($filter)) return $this->INVALID_DATA("Array", gettype($filter));




        // Each key spesific
        foreach($filter as $filterkey => $filter_function_or_array) {
            // look for JSON data and decode if found
            if (isset($arr[$filterkey]) && in_array($this->EXPECT_JSON, $flags)) {
                if ($this->VALIDATE_JSON($arr[$filterkey])) {
                    // if json then decode
                    $arr[$filterkey] = json_decode($arr[$filterkey]);

                } else if (is_string($arr[$filterkey]) && $this->VALIDATE_JSON(stripslashes($arr[$filterkey]))) {
                    // if formdata added slashes -> remove and decode
                    $arr[$filterkey] = json_decode(stripslashes($arr[$filterkey]));
                }
            }

            // if object
            if (isset($arr[$filterkey]) && is_object($arr[$filterkey])) $arr[$filterkey] = (array) $arr[$filterkey];

            // if function
            if (is_callable($filter_function_or_array)) {
                $return_array[$filterkey] = $this->Sanitize_Variable($arr[$filterkey] ?? null, $filter_function_or_array, $flags);
                continue;
            }

            // if object
            if (is_object($filter_function_or_array)) $filter_function_or_array = (array) $filter_function_or_array;

            // if array
            if (is_array($filter_function_or_array)) {
                // if array with one filter
                if(count($filter_function_or_array) == 1 && empty(array_keys($filter_function_or_array)[0])) {
                    $return_array[$filterkey] = $this->FUNCTION_SANITIZE_ARRAY_SINGLEKEY(array(), $arr[$filterkey] ?? null, $filter_function_or_array, $flags);
                    continue;
                }

                // if array with multiple filters
                $return_array[$filterkey] = $this->Sanitize_Array($arr[$filterkey] ?? null, $filter_function_or_array, $flags);
                continue;
            }
        }

        // Return result
        return $return_array;
    }
    public function FUNCTION_ADD_BADFIELD                   ($key, $value) {
        if (is_array($value) && count($value) === 2) return $value[1];
        return $key;
    }

    /* Helper Sanitizer */
    public function REPLACE_ACCENTS                         ($str): string {
        // Remove Accent characters like: á => a

        // Credits: Darryl Snow
        // https://gist.github.com/darryl-snow/3817411

        if(strlen($str) ===  0) return "";
        $str = htmlentities($str, ENT_COMPAT, "UTF-8");
        $str = preg_replace('/&([a-zA-Z])(uml|acute|grave|circ|tilde);/', '$1', $str);
        return html_entity_decode($str);
    }
    public function REPLACE_NONPRINTABLE                    ($str): string {
        // ASCII & UTF-8 compatible
        if(strlen($str) == 0) return "";
        return preg_replace('/[\x00-\x1F\x7F\xA0]/u', '', $str);
    }

    /* Helper Validations */
    public function NOT_SANITIZABLE                         ($var) {
        return ($var === '' || is_callable($var) || is_object($var) || is_array($var));
    }
    public function VALIDATE_REQUIRED_FIELDS_SINGLEKEY      ($arr, $required_array, $flags) {
        $return_array = array();
        $badfields    = array();

        // error prevention: turn inouts into array
        if (!is_array($arr))            $arr = array($arr);
        if (!is_array($flags))          $flags = array($flags);
        if (!is_array($required_array)) $required_array = array($required_array);

        // foreach $arr
        foreach ($arr as $arrkey => $arrvalue) {
            // check if required field. Skip if not.
            if (!isset($required_array[$arrkey]))   continue;

            // Check if required = array(bool, return string);
            if (is_array($required_array[$arrkey]) && count($required_array[$arrkey]) === 2 && $required_array[$arrkey][0] === false) continue;

            // Check if required = bool
            if ($required_array[$arrkey] === false) continue;


            // no value / nothing to validate
            if (!isset($arrvalue)) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($arrkey, $required_array[$arrkey]); continue; }
            
            // error prevention
            if (is_object($arrvalue)) $arrvalue = (array) $arrvalue;

            // if array, then check if empty
            if (is_array($required_array[0])) {
                if ($this->VALIDATE_REQUIRED_FIELDS($arrvalue, $required_array[0], $flags) !== true) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($arrkey, $required_array[$arrkey]); continue; }
                $return_array[] = $arrvalue;
                continue;
            }

            // if null / undefined value
            if ($arrvalue === null)  { $badfields[] = $this->FUNCTION_ADD_BADFIELD($arrkey, $required_array[$arrkey]); continue; }

            $return_array[] = $arrvalue;
        }

        // if any bad fields
        if (count($badfields) > 0) return $badfields;

        // Meet all requirements
        return true;
    }
    public function VALIDATE_REQUIRED_FIELDS_MULTIPLEKEYS   ($arr, $required_array, $flags) {
        $return_array = array();
        $badfields    = array();

        // Error prevention: if not array
        if (!is_array($arr))            $arr = array($arr);
        if (!is_array($flags))          $flags = array($flags);
        if (!is_array($required_array)) $required_array = array($required_array);

        // Each key spesific
        foreach($required_array as $requirekey => $require_function_or_array) {
            // Check if required = array(bool, return string);
            if (is_array($require_function_or_array) && count($require_function_or_array) === 2 && $require_function_or_array[0] === false) continue;

            // Check if required = bool
            if($require_function_or_array === false) continue;


            // if key don't exist in array
            if(!isset($arr[$requirekey])) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }

            // if function
            if (is_callable($require_function_or_array)) {
                // if null / undefined value
                if ($arr[$requirekey] === null) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
            }

            // if object
            if (is_object($arr[$requirekey]))           $arr[$requirekey] = (array) $arr[$requirekey];
            if (is_object($require_function_or_array))  $require_function_or_array = (array) $require_function_or_array;

            // if array
            if (is_array($require_function_or_array)) {
                // if array with one filter
                if(count($require_function_or_array) == 1 && empty(array_keys($require_function_or_array)[0])) {
                    if ($this->VALIDATE_REQUIRED_FIELDS_SINGLEKEY($arr[$requirekey], $require_function_or_array, $flags) !== true) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
                    $return_array[$requirekey] = $arr[$requirekey];
                    continue;
                }

                // if empty array
                if (is_array($arr[$requirekey]) && count($arr[$requirekey]) === 0) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }

                // if null / undefined value
                if ($arr[$requirekey] === null) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
                $return_array[$requirekey] = $arr[$requirekey];
                continue;
            }
            // if array
            if (is_array($arr[$requirekey])) {
                // if array with one filter
                if(count($arr[$requirekey]) == 1 && empty(array_keys($arr[$requirekey])[0])) {
                    if ($this->VALIDATE_REQUIRED_FIELDS_SINGLEKEY($arr[$requirekey], $require_function_or_array, $flags) !== true) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
                    $return_array[$requirekey] = $arr[$requirekey];
                    continue;
                }

                // if empty array
                if (count($arr[$requirekey]) === 0) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }

                // if null / undefined value
                if ($arr[$requirekey] === null) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
                $return_array[$requirekey] = $arr[$requirekey];
                continue;
            }

            // if null / undefined value
            if ($arr[$requirekey] === null) { $badfields[] = $this->FUNCTION_ADD_BADFIELD($requirekey, $require_function_or_array); continue; }
            $return_array[$requirekey] = $arr[$requirekey];
        }

        // if any bad fields
        if (count($badfields) > 0) return $badfields;

        // Meet all requirements
        return true;
    }
}

?>
