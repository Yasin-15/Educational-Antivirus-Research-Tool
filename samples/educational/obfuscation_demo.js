// Obfuscation Techniques Demonstration - EDUCATIONAL ONLY
// This JavaScript file demonstrates various obfuscation methods
// It contains NO malicious code and is completely harmless

// 1. String Obfuscation
var _0x1234 = ["hello", "world", "educational", "demo"];
var greeting = _0x1234[0] + " " + _0x1234[1];

// 2. Base64 Encoding
var encoded = "ZWR1Y2F0aW9uYWwgZGVtbw=="; // "educational demo"
var decoded = atob(encoded);

// 3. Character Code Obfuscation  
var obfuscated = String.fromCharCode(101,100,117,99,97,116,105,111,110,97,108);

// 4. Hexadecimal Encoding
var hex_string = "\x65\x64\x75\x63\x61\x74\x69\x6f\x6e\x61\x6c";

// 5. Function Name Obfuscation
var _0xabcd = function() {
    return "This is an educational demonstration";
};

// 6. Control Flow Obfuscation
var result = "";
for(var i = 0; i < 10; i++) {
    if(i % 2 == 0) {
        result += "even ";
    } else {
        result += "odd ";
    }
}

// Educational Note: Real malware uses these techniques to hide
// malicious code from static analysis tools
console.log("Educational obfuscation demo completed");
