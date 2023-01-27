<?php

/**
 *                  Sanitizer
 * If you want to trust the data and make sure
 * an object or array have the keys you
 * need without manually checking each one.
 * 
 * @author Thomas Tufta Løberg
 * 
 * 
 * Supported formats:
 *      Raw                     # No sanitize
 *      Array   (multi layer)   # One or multiple filters
 *      Object  (multi layer)   # One or multiple filters
 *      Double             	# Sanitize Double
 *      Float              	# Sanitize Float
 *      Integer                 # Sanitize Integer
 *      String                  # Sanitize String   (flags optional)
 *      Filename                # Sanitize Filename (flag ALLOW_NORWEGIAN optional)
 *      URL                     # Sanitize URL
 *      Email                   # Sanitize Email
 */

namespace tloberg;

class Sanitizer {
    /**
     * FLAGS
     */
    public $ALLOW_QUOTES = "ALLOW_QUOTES";          // Allow single and double quotes in string
    public $NO_TRIM      = "NO_TRIM";               // Allow white-space at ends in string
    public $NO_HTMLSTRIP = "NO_HTMLSTRIP";          // Allow HTML tags in string
    public $ALLOW_NORWEGIAN = "ALLOW_NORWEGIAN";    // Allow norwegian letters


    public function __construct() {}
  

    public function Sanitize_Variable($var, $filter) {
        return $filter($var);
    }
    public function Sanitize_Array($arr, $filter) {
        $return_array = array();

        if(is_array($filter)) {
            // filter keys with filters provided
            foreach ($filter as $key => $filter_function) {
                if(isset($arr[$key])) {
                    if(is_array($filter_function)) {
                        $return_array[$key] = $this->Sanitize_Array($arr[$key], $filter_function);
                    } else {
                        $return_array[$key] = $filter_function($arr[$key]);
                    }
                }
                else {
                    // no existing key. add new:
                    $return_array[$key] = null;
                }
            }
        }
        else {
            // only one filter provided. Filter all keys with this filter
            foreach ($arr as $key => $value) {
                if(isset($arr[$key])) {
                    $return_array[$key] = $filter($value);
                }
                else {
                    // no existing key. add new:
                    $return_array[$key] = null;
                }
            }
        }

        return $return_array;
    }
    public function Sanitize_Object($obj, $filter) {
        return (object) $this->Sanitize_Array((array) $obj, (array) $filter);
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

    public function FILTER_DOUBLE() {
        return function($var) { return $this->FUNCTION_FILTER_DOUBLE($var); };
    }
    public function FUNCTION_FILTER_DOUBLE($var) {
        return (double) filter_var($var, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    }

    public function FILTER_FLOAT() {
        return function($var) { return $this->FUNCTION_FILTER_FLOAT($var); };
    }
    public function FUNCTION_FILTER_FLOAT($var) {
        return (float) filter_var($var, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    }

    public function FILTER_INTEGER() {
        return function($var) { return $this->FUNCTION_FILTER_INTEGER($var); };
    }
    public function FUNCTION_FILTER_INTEGER($var) {
        return (integer) filter_var($var, FILTER_SANITIZE_NUMBER_INT);
    }

    public function FILTER_STRING($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_STRING($var, $flags);
        };
    }
    public function FUNCTION_FILTER_STRING($var, $flags=null) {
        // error prevention
        if(!is_array($flags)) { $flags = array($flags); }

        // Remove everything except these characters:
        
        // 0-9          // Numbers
        // a-zA-Z       // English alphabet
        // æøåÆØÅ       // Norwegian letters
        // ,\\\\.\-\/=$
		    // |\*\+\[\]!\?
		    // _:;@#%&\(\)  // Symbols 3/3
        // \n\r         // New line on Linux & Windows
        //  \t          // Spaces + Tabs
        // \"\'         // Single & Double quotes - only if ALLOW_QUOTES flag present


        // Default regex / allowed chars
        $regex = "0-9a-zA-Z,\\\\.\-\/=$|\*\+\[\]!\?_:;@#%&\(\) \n\r\t";


        // if ALLOW_NORWEGIAN flag present then add flag
        if(in_array($this->ALLOW_NORWEGIAN, $flags)) {
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
        return preg_replace("/[^{$regex}]/", "", $var);
    }

    public function FILTER_FILENAME($flags=null) {
        return function($var) use ($flags) {
            return $this->FUNCTION_FILTER_FILENAME($var, $flags);
        };
    }
    public function FUNCTION_FILTER_FILENAME($var, $flags=null) {
        // error prevention
        if(!is_array($flags)) { $flags = array($flags); }

        // Default regex / allowed chars
        $regex = "a-zA-Z0-9_\-\.";

        // if ALLOW_NORWEGIAN flag present then add flag
        if(in_array($this->ALLOW_NORWEGIAN, $flags)) {
            $regex .= "æøåÆØÅ";
        }

        // non optional function which removes unwanted chars
        $var = trim($var);
        $var = strip_tags($var);

        return (string) preg_replace("/[^{$regex}]/", "", $var);
    }

    public function FILTER_URL() {
        return function($var) { return $this->FUNCTION_FILTER_URL($var); };
    }
    public function FUNCTION_FILTER_URL($var) {
        return (string) filter_var($var, FILTER_SANITIZE_URL);
    }

    public function FILTER_EMAIL() {
        return function($var) { return $this->FUNCTION_FILTER_EMAIL($var); };
    }
    public function FUNCTION_FILTER_EMAIL($var) {
        return (string) filter_var($var, FILTER_SANITIZE_EMAIL);
    }
}

?>
