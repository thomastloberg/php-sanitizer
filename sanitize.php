<?php

/**
 * 
 *                 PHP Sanitizer
 * 
 * 
 * @version 1.1.3
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
 * INVALID_DATA Default answer: null
 * 
 * 
 * 
 * Supported formats:
 *      Raw             # No sanitize
 *      Array           # Filter Array = Output Array. (optional flags: DEEP_ARRAY, EXPECT_JSON)
 *      Object          # Filter Object = Output Object. (optional flags: DEEP_ARRAY, EXPECT_JSON)
 *      Double          # Sanitize Double    (optional flags: NO_VALIDATION, STRICT)
 *      Float           # Sanitize Float     (optional flags: NO_VALIDATION, STRICT)
 *      Integer         # Sanitize Integer   (optional flags: NO_VALIDATION, STRICT)
 *      Boolean         # Sanitize Boolean
 *      String          # Sanitize String    (optional flags: DENY_NORWEGIAN, NO_TRIM, NO_HTMLSTRIP, ALLOW_QUOTES)
 *      Filename        # Sanitize Filename  (optional flags: DENY_NORWEGIAN)
 *      Filepath        # Sanitize Filepath  (optional flags: DENY_NORWEGIAN)
 *      URL             # Sanitize URL       (optional flags: NO_VALIDATION)
 *      Email           # Sanitize Email     (optional flags: NO_VALIDATION)
 *      Year            # Sanitize Year      (optional flags: NO_VALIDATION)
 *      Timestamp       # Sanitize timestamp (optional flags: NO_VALIDATION)
 *      Date            # Sanitize Date      (optional flags: NO_VALIDATION)
 *      DateTime        # Sanitize DateTime  (optional flags: NO_VALIDATION)
 *      Custom
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

    
    public function __construct() {}
    public function INVALID_DATA($expected_datatype=null, $received_datetype=null) {
        /**
         * Default: return null if invalid data (no data or wrong type)
         */
        return null; // Comment this if you want more detailed response on INVALID DATA


        /**
         * Optional: return Invalid {type} or No data
         */
        $return_text = "";

        if(empty($expected_datatype)) {

            if(empty($received_datetype)) {
                $return_text = "No data";
            }
            else {
                $return_text = "Invalid (" . ucwords(strtolower($received_datetype)) . ")";
            }

        }
        else {

            $return_text = "Invalid. Expected: " .$expected_datatype;

            if(!empty($received_datetype)) {
                $return_text .= " (" . ucwords(strtolower($received_datetype)) . ")";
            }

        }

        return $return_text;
    }
  


    public function Sanitize_Variable($var, $filter, $flags=null) {
        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // error prevention: if function passed into input array
        if(!is_callable($filter)) {
            return $this->INVALID_DATA(null, "Function");
        }

        // look for JSON data and decode if found
        if(in_array($this->EXPECT_JSON, $flags)) {
            if($this->FUNCTION_VALIDATE_JSON($var)) {
                $var = json_decode($var);
            }
        }

        if(is_object($var)) {
            $var = (array) $var;
        }
        
        return $filter($var);
    }
    public function Sanitize_Array($arr, $filter, $flags=null) {
        //prepair return array based of $filter
        $return_array = array();

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // error prevention: if function passed into input array
        if(is_callable($arr)) {
            return $this->INVALID_DATA(null, "Function");
        }

        // make sure we are working with arrays not objects
        if(is_object($arr)) {
            $arr = (array) $arr;
        } else if(is_array($arr)) {
            // perfect
        } else {
            $arr = array($arr);
        }


        if(is_callable($filter)) {


            // only one filter provided. Filter all keys with this filter
            foreach ($arr as $key => $value) {
                if(isset($value)) {

                    // look for JSON data and decode if found
                    if(in_array($this->EXPECT_JSON, $flags)) {
                        if($this->FUNCTION_VALIDATE_JSON($value)) {
                            $value = json_decode($value);
                        }
                    }

                    // convert object to array with keys
                    if(is_object($value)) {
                        $value = (array) $value;
                    }


                    // if DEEP_ARRAY then sanitize all object properties and array keys with filter
                    if(in_array($this->DEEP_ARRAY, $flags)) {

                        if(is_object($value)) {
                            $return_array[$key] = $this->Sanitize_Array((array) $value, $filter, $flags);
                        }
                        elseif(is_array($value)) {
                            $return_array[$key] = $this->Sanitize_Array($value, $filter, $flags);
                        }
                        else {
                            $return_array[$key] = $this->Sanitize_Variable($value, $filter, $flags);
                        }

                    }
                    else {

                        if(is_object($value) && is_object($filter)) {
                            $return_array[$key] = $this->Sanitize_Array((array) $value, $filter, $flags);
                        }
                        elseif(is_array($value) && is_array($filter)) {
                            $return_array[$key] = $this->Sanitize_Array($value, $filter, $flags);
                        }
                        elseif(is_object($value)) {
                            $return_array[$key] = $this->INVALID_DATA(null, "Object");
                        }
                        elseif(is_array($value)) {
                            $return_array[$key] = $this->INVALID_DATA(null, "Array");
                        }
                        else {
                            $return_array[$key] = $this->Sanitize_Variable($value, $filter, $flags);
                        }

                    }
                    
                }
                else {
                    // no existing key
                    $return_array[$key] = $this->INVALID_DATA();
                }
            }

            return $return_array;

        }


        // if object then change to array for each manipulation
        if(is_object($filter)) { $filter = (array) $filter; }


        if(is_array($filter)) {

            if(count($filter) == 1 && array_keys($filter)[0] == 0) {

                // filter all input array by this one filter
                foreach ($arr as $key => $value) {
                    if(isset($value)) {

                        // look for JSON data and decode if found
                        if(in_array($this->EXPECT_JSON, $flags)) {
                            if($this->FUNCTION_VALIDATE_JSON($value)) {
                                $value = json_decode($value);
                            }
                        }

                        // convert object to array with keys
                        if(is_object($value)) {
                            $value = (array) $value;
                        }


                        // if DEEP_ARRAY then sanitize all object properties and array keys with filter
                        if(in_array($this->DEEP_ARRAY, $flags)) {

                            if(is_object($value)) {
                                $return_array[$key] = $this->Sanitize_Array((array) $value, $filter[0], $flags);
                            }
                            elseif(is_array($value)) {
                                $return_array[$key] = $this->Sanitize_Array($value, $filter[0], $flags);
                            }
                            else {
                                $return_array[$key] = $this->Sanitize_Variable($value, $filter[0], $flags);
                            }

                        }
                        else {

                            if(is_object($value) && is_object($filter[0])) {
                                $return_array[$key] = $this->Sanitize_Array((array) $value, $filter[0], $flags);
                            }
                            elseif(is_array($value) && is_array($filter[0])) {
                                $return_array[$key] = $this->Sanitize_Array($value, $filter[0], $flags);
                            }
                            elseif(is_object($value)) {
                                $return_array[$key] = $this->INVALID_DATA(null, "Object");
                            }
                            elseif(is_array($value)) {
                                $return_array[$key] = $this->INVALID_DATA(null, "Array");
                            }
                            else {
                                $return_array[$key] = $this->Sanitize_Variable($value, $filter[0], $flags);
                            }

                        }

                    }
                    else {
                        // no existing key
                        $return_array[$key] = $this->INVALID_DATA();
                    }
                }

            }
            else {

                // filter keys with filters provided
                foreach ($filter as $key => $filter_argument) {
                    if(isset($arr[$key])) {

                        // look for JSON data and decode if found
                        if(in_array($this->EXPECT_JSON, $flags)) {
                            if($this->FUNCTION_VALIDATE_JSON($arr[$key])) {
                                $arr[$key] = json_decode($arr[$key]);

                                if(is_object($arr[$key])) {
                                    $arr[$key] = (array) $arr[$key];
                                }
                            }
                        }

                        // convert object to array with keys
                        if(is_object($arr[$key])) {
                            $arr[$key] = (array) $arr[$key];
                        }


                        if(is_callable($filter_argument)) {
                            $return_array[$key] = $filter_argument($arr[$key]);
                        }
                        elseif(is_object($filter_argument)) {
                            // if $filter_function is a object then change to array
                            $return_array[$key] = $this->Sanitize_Array($arr[$key], (array) $filter_argument, $flags);
                        }
                        elseif(is_array($filter_argument)) {
                            $return_array[$key] = $this->Sanitize_Array($arr[$key], $filter_argument, $flags);
                        }
                        else {
                            $return_array[$key] = $filter_argument;
                        }
                    }
                    else {
                        // no existing key / empty data

                        if(is_callable($filter_argument)) {
                            // can't filter empty data
                            $return_array[$key] = $this->INVALID_DATA();
                        }
                        elseif(is_object($filter_argument)) {
                            // can't filter empty data
                            $return_array[$key] = $this->INVALID_DATA("Object");
                        }
                        elseif(is_array($filter_argument)) {
                            // can't filter empty data
                            $return_array[$key] = $this->INVALID_DATA("Array");
                        }
                        else {
                            // set key to set value
                            $return_array[$key] = $filter_argument;
                        }
                    }
                }

            }


        }
        else {

            // No filter

        }


        return $return_array;
    }
    public function Sanitize_Object($obj, $filter, $flags=null) {
        if(is_object($obj)) { $obj = (array) $obj; }
        if(is_object($filter)) { $filter = (array) $filter; }

        return (object) $this->Sanitize_Array($obj, $filter, $flags);
    }



    /**
     * Helper Functions
     */
    public function NOT_SANITIZABLE($var) {
        return (empty($var) || is_callable($var) || is_object($var) || is_array($var));
    }
    public function RETURN_IF_NOT_EMPTY($var, $datatype=null) {
        if(empty($var)) {
            if(empty($datatype)) {
                return $this->INVALID_DATA(gettype($var));
            } else {
                return $this->INVALID_DATA($datatype);
            }
        }

        return $var;
    }


    /**
     * Filters
     */
    public function FILTER_RAW() {
        return function($var) { return $this->FUNCTION_FILTER_RAW($var); };
    }
    public function FUNCTION_FILTER_RAW($var) {
        return $var;
    }

    public function FILTER_BOOLEAN() {
        return function($var) {
            return $this->FUNCTION_FILTER_BOOLEAN($var);
        };
    }
    public function FUNCTION_FILTER_BOOLEAN($var) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Boolean"); }

        // quick check with simple object convertion if true
        if($var == TRUE) {
            return true;
        }

        // sanitize boolean. Returns: True / False / null
        $var = filter_var($var, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if($var === null) {
            return $this->INVALID_DATA("Boolean");
        } else {
            return $this->RETURN_IF_NOT_EMPTY((boolean) $var);
        }
    }

    public function FILTER_INTEGER($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_INTEGER($var, $flags);
        };
    }
    public function FUNCTION_FILTER_INTEGER($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Integer"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // sanitize variable
        $var = filter_var($var, FILTER_SANITIZE_NUMBER_INT);

         // if NO_VALIDATION flag present then return without validation
         if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((integer) $var);
        }

        // return null if no valid integer
        if(in_array($this->STRICT, $flags)) {

            // Strict validation. Float / Double => Not valid
            if($this->FUNCTION_VALIDATE_INTEGER_STRICT($var)) {
                return $this->RETURN_IF_NOT_EMPTY((integer) $var);
            } else {
                return $this->INVALID_DATA("Integer");
            }

        }
        else {

            // Not strict: Float / Double / Integer => Valid
            if($this->FUNCTION_VALIDATE_INTEGER($var)) {
                return $this->RETURN_IF_NOT_EMPTY((integer) $var);
            } else {
                return $this->INVALID_DATA("Integer");
            }

        }
    }

    public function FILTER_DOUBLE($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DOUBLE($var, $flags);
        };
    }
    public function FUNCTION_FILTER_DOUBLE($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Double"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // sanitize variable
        $var = filter_var($var, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);

         // if NO_VALIDATION flag present then return without validation
         if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((double) $var);
        }

        // return null if no valid integer
        if(in_array($this->STRICT, $flags)) {

            // Strict validation. Float => Not valid
            if($this->FUNCTION_VALIDATE_DOUBLE_STRICT($var)) {
                return $this->RETURN_IF_NOT_EMPTY((double) $var);
            } else {
                return $this->INVALID_DATA("Double");
            }

        }
        else {

            // Not strict: Float / Double / Integer => Valid
            if($this->FUNCTION_VALIDATE_DOUBLE($var)) {
                return $this->RETURN_IF_NOT_EMPTY((double) $var);
            } else {
                return $this->INVALID_DATA("Double");
            }

        }
    }

    public function FILTER_FLOAT($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FLOAT($var, $flags);
        };
    }
    public function FUNCTION_FILTER_FLOAT($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Float"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // sanitize variable
        $var = filter_var($var, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);

         // if NO_VALIDATION flag present then return without validation
         if(in_array($this->NO_VALIDATION, $flags)) {
            return$this->RETURN_IF_NOT_EMPTY((float) $var);
        }

        // return null if no valid integer
        if(in_array($this->STRICT, $flags)) {

            // Strict validation. Double => Not valid
            if($this->FUNCTION_VALIDATE_FLOAT_STRICT($var)) {
                return $this->RETURN_IF_NOT_EMPTY((float) $var);
            } else {
                return $this->INVALID_DATA("Float");
            }

        }
        else {

            // Not strict: Float / Double / Integer => Valid
            if($this->FUNCTION_VALIDATE_FLOAT($var)) {
                return $this->RETURN_IF_NOT_EMPTY((float) $var);
            } else {
                return $this->INVALID_DATA("Float");
            }

        }
    }

    public function FILTER_STRING($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_STRING($var, $flags);
        };
    }
    public function FUNCTION_FILTER_STRING($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("String"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }


        // Remove everything except these characters:
        
        // 0-9          // Numbers
        // a-zA-Z       // English alphabet
        // æøåÆØÅ       // Norwegian letters
        // ,\\.\-\/=$
		// |\*\+\[\]!\?
		// _:;@#%&\(\)  // Symbols 3/3
        // \n\r         // New line on Linux & Windows
        //  \t          // Spaces + Tabs
        // \"\'         // Single & Double quotes - only if ALLOW_QUOTES flag present


        // Default regex / allowed chars
        $regex = "0-9a-zA-Z,\\.\-\/=$|\*\+\[\]!\?_:;@#%&\(\) \n\r\t";


        // if DENY_NORWEGIAN flag not present then add flag
        if(!in_array($this->DENY_NORWEGIAN, $flags)) {
            $regex .= "æøåÆØÅ";
        }

        // if ALLOW_QUOTES flag present then add flag
        if(in_array($this->ALLOW_QUOTES, $flags)) {
            $regex .= "\"\'";
        }

		    // remove outer white-space - only if NO_TRIM flag isn't present
        if(!in_array($this->NO_TRIM, $flags)) {
		    $var = trim($var);
        }

        // Default: Remove html tags, example: <p></p> - only if NO_HTMLSTRIP flag isn't present
        if(!in_array($this->NO_HTMLSTRIP, $flags)) {
            $var = strip_tags($var);
        } else {
            // NO_HTMLSTRIP then add < and > to allowed chars
            $regex .= "\<\>";
        }

        // Remove all chars not in regex match
        $var = preg_replace("/[^{$regex}]/", "", $var);

        return $this->RETURN_IF_NOT_EMPTY((string) $var);
    }

    public function FILTER_FILENAME($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FILENAME($var, $flags);
        };
    }
    public function FUNCTION_FILTER_FILENAME($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Filename"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // Default regex / allowed chars
        $regex = "a-zA-Z0-9_\-\.\s";

        // if DENY_NORWEGIAN flag not present then add flag
        if(!in_array($this->DENY_NORWEGIAN, $flags)) {
            $regex .= "æøåÆØÅ";
        }

        // non optional function which removes unwanted chars
        $var = trim($var);
        $var = strip_tags($var);

        $var = preg_replace("/[^{$regex}]/", "", $var);

        return $this->RETURN_IF_NOT_EMPTY((string) $var, "Filename");
    }

    public function FILTER_FILEPATH($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FILEPATH($var, $flags);
        };
    }
    public function FUNCTION_FILTER_FILEPATH($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Filepath"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // Default regex / allowed chars
        $regex = "a-zA-Z0-9_\-\.\\\\\/:\s";

        // if DENY_NORWEGIAN flag not present then add flag
        if(!in_array($this->DENY_NORWEGIAN, $flags)) {
            $regex .= "æøåÆØÅ";
        }

        // non optional function which removes unwanted chars
        $var = trim($var);
        $var = strip_tags($var);
        $var = preg_replace("/[^{$regex}]/", "", $var);

        return $this->RETURN_IF_NOT_EMPTY((string) $var, "Filepath");
    }

    public function FILTER_URL($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_URL($var, $flags);
        };
    }
    public function FUNCTION_FILTER_URL($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("URL"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // sanitize url
        $var = filter_var($var, FILTER_SANITIZE_URL);

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "URL");
        }

        // return url if validated true
        if($this->FUNCTION_VALIDATE_URL($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "URL");
        }

        return $this->INVALID_DATA("URL");
    }

    public function FILTER_EMAIL($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_EMAIL($var, $flags);
        };
    }
    public function FUNCTION_FILTER_EMAIL($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Email"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // sanitize email
        $var = filter_var($var, FILTER_SANITIZE_EMAIL);

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Email");
        }

        // return variable if valid Email address
        if($this->FUNCTION_VALIDATE_EMAIL($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Email");
        } else {
            return $this->INVALID_DATA("Email");
        }
    }

    public function FILTER_YEAR($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_INTEGER($var, $flags);
        };
    }
    public function FUNCTION_FILTER_YEAR($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Year"); }

        // sanitize year
        $var = (integer) filter_var($var, FILTER_SANITIZE_NUMBER_INT);

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Year");
        }

        if($this->FUNCTION_VALIDATE_YEAR($var)) {
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Year");
        }

        return $this->INVALID_DATA("Year");
    }

    public function FILTER_TIMESTAMP($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_TIMESTAMP($var, $flags);
        };
    }
    public function FUNCTION_FILTER_TIMESTAMP($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Timestamp"); }

        // sanitize timestmp
        $var = (integer) filter_var($var, FILTER_SANITIZE_NUMBER_INT);

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Timestamp");
        }

        if($this->FUNCTION_VALIDATE_TIMESTAMP($var)) {
            return $this->RETURN_IF_NOT_EMPTY((integer) $var, "Timestamp");
        }

        return $this->INVALID_DATA("Timestamp");
    }

    public function FILTER_DATE($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DATE($var, $flags);
        };
    }
    public function FUNCTION_FILTER_DATE($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("Date"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // non optional function which removes unwanted chars
        $var = trim($var);
        $var = strip_tags($var);

        // Default regex / allowed chars
        $regex = "0-9\-\.\\\\\/:";

        $var = preg_replace("/[^{$regex}]/", "", $var);
        

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Date");
        }

        // return variable if valid Email address
        if($this->FUNCTION_VALIDATE_DATE($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "Date");
        } else {
            return $this->INVALID_DATA("Date");
        }
    }

    public function FILTER_DATETIME($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_DATETIME($var, $flags);
        };
    }
    public function FUNCTION_FILTER_DATETIME($var, $flags=null) {
        // error prevention: if $var is string then return null
        if($this->NOT_SANITIZABLE($var)) { return $this->INVALID_DATA("DateTime"); }

        // error prevention: if flags isn't array then put the flag or NULL into an array
        if(!is_array($flags)) { $flags = array($flags); }

        // non optional function which removes unwanted chars
        $var = trim($var);
        $var = strip_tags($var);

        // Default regex / allowed chars
        $regex = "0-9\-\.\\\\\/:\s";

        $var = preg_replace("/[^{$regex}]/", "", $var);
        

        // if NO_VALIDATION flag present then return without validation
        if(in_array($this->NO_VALIDATION, $flags)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "DateTime");
        }

        // return variable if valid Email address
        if($this->FUNCTION_VALIDATE_DATETIME($var)) {
            return $this->RETURN_IF_NOT_EMPTY((string) $var, "DateTime");
        } else {
            return $this->INVALID_DATA("DateTime");
        }
    }



    /**
     * VALIDATION
     */
    public function FUNCTION_VALIDATE_INTEGER($var) {
        return is_numeric($var);
    }
    public function FUNCTION_VALIDATE_INTEGER_STRICT($var) {
        return (is_numeric($var) && !is_float($var) && !is_double($var));
    }

    public function FUNCTION_VALIDATE_DOUBLE($var) {
        return (is_numeric($var) || is_double($var) || is_float($var));
    }
    public function FUNCTION_VALIDATE_DOUBLE_STRICT($var) {
        return (is_numeric($var) && is_double($var) && !is_float($var));
    }

    public function FUNCTION_VALIDATE_FLOAT($var) {
        return (is_numeric($var) || is_float($var) || is_double($var));
    }
    public function FUNCTION_VALIDATE_FLOAT_STRICT($var) {
        return (is_numeric($var) && is_float($var) && !is_double($var));
    }

    public function FUNCTION_VALIDATE_URL($var) {
        return filter_var($var, FILTER_VALIDATE_URL);
    }

    public function FUNCTION_VALIDATE_EMAIL($var) {
        return filter_var($var, FILTER_VALIDATE_EMAIL);
    }

    public function FUNCTION_VALIDATE_YEAR($var) {
        return (is_numeric($var) && strlen($var) === 4);
    }

    public function FUNCTION_VALIDATE_TIMESTAMP($var) {
        return (ctype_digit($var) && strtotime(date('Y-m-d H:i:s', $var)) === (int)$var);
    }

    public function FUNCTION_VALIDATE_DATE($var) {
        // YYYY-MM-DD
        return preg_match("/^[0-9]{4}[\\|\/|\.|\-][0-9]{1,2}[\\|\/|\.|\-][0-9]{1,2}$/", $var);
    }

    public function FUNCTION_VALIDATE_DATETIME($var) {
        // YYYY-MM-DD HH:MM:SS
        return preg_match("/^[0-9]{4}[\\|\/|\.|\-][0-9]{1,2}[\\|\/|\.|\-][0-9]{1,2}\s[0-9]{1,2}[\.|\-|\:][0-9]{1,2}[\.|\-|\:][0-9]{1,2}$/", $var);
    }

    public function FUNCTION_VALIDATE_JSON($var) {
        // not string == not JSON
        if(!is_string($var)) return false;

        // array or object
        if(!preg_match("/^({|\[).+(\]|})$/", $var)) return false;

        // JSON checker
        return !preg_match('/[^,:{}\\[\\]0-9.\\-+Eaeflnr-u \\n\\r\    ]/', preg_replace('/"(\\.|[^"\\\\])*"/', '', $var));
    }
}

?>
