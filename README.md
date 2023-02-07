# PHP Sanitizer  
Powerfull PHP Sanitizer for any variable.  
  
If you want to trust the data and make sure an object or array have the keys you need without manually checking each one.  
After sanitizing variable it will get passed through a validation proces and return INVALID_DATA() if no data / invalid INVALID_DATA Default answer: null.  

<br>
<br>

## How to  
1. Require once the class `require_once "/parent-folder/sanitize.php";`.  
2. Initialize the class like so `$Sanitizer = new \tloberg\Sanitizer();`.  
3. See examples for how to use the sanitizer [here](https://github.com/thomastloberg/php-sanitizer/blob/master/example.php).  

<br>
<br>

## Supported formats  
1. **Raw**  
  No sanitize  
  
2. **Array**  
  One or multiple filters functions. One function in filter array will run function on all keys in input array  
  
3. **Object**  
  One or multiple filters functions. One function in filter object will run function on all keys in input object  
  
4. **Double**  
  Sanitize Double (optional flags: NO_VALIDATION, STRICT)  
  
5. **Float**  
  Sanitize Float (optional flags: NO_VALIDATION, STRICT)  
  
6. **Integer**  
  Sanitize Integer (optional flags: NO_VALIDATION, STRICT)  
  
7. **Boolean**  
  Sanitize Boolean  
  
8. **String**  
  Sanitize String   (optional flags: DENY_NORWEGIAN, NO_TRIM, NO_HTMLSTRIP, ALLOW_QUOTES)  
  
9. **Filename**  
  Sanitize Filename (optional flags: DENY_NORWEGIAN)  
  
10. **Filepath**  
  Sanitize Filepath (optional flags: DENY_NORWEGIAN)  
  
11. **URL**  
  Sanitize URL (optional flags: NO_VALIDATION)  
  
12. **Email**  
  Sanitize Email (optional flags: NO_VALIDATION)  
  
13. **Year**  
  Sanitize Year (optional flags: NO_VALIDATION)  
  
14. **Timestamp**  
  Sanitize Timestamp (optional flags: NO_VALIDATION)  
  
15. **Date**  
  Sanitize Date (optional flags: NO_VALIDATION)  
  
16. **DateTime**  
  Sanitize DateTime (optional flags: NO_VALIDATION)  
  
17. **Custom**  
  Create your own filter

<br>
<br>

## Validation formats  
1. **Integer**  
  All numbers (double, float, integer) accepted  
  
2. **Integer (strict)**  
  ONLY integer
  
3. **Double**  
  All numbers (double, float, integer) accepted  
  
4. **Double (strict)**  
  ONLY double  
  
5. **Float**  
  All numbers (double, float, integer) accepted  
  
6. **Float (strict)**  
  ONLY float  
  
7. **URL**  
  
8. **Email**  
  
9. **Year**  
  
10. **Timestamp**  
  
11. **Date**  
  
12. **Datetime**  
