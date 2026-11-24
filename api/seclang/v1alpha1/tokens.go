/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

// VariableName is one SecLang variable or collection.
// selector is the key, or a /regex/ selector when it starts and ends with a slash.
// count emits the & prefix. exclude emits the ! prefix.

// +kubebuilder:validation:Enum=ARGS_COMBINED_SIZE;AUTH_TYPE;DURATION;FILES_COMBINED_SIZE;FILES_NAMES;FILES_SIZES;FILES_TMP_CONTENT;FILES_TMPNAMES;FULL_REQUEST;FULL_REQUEST_LENGTH;HIGHEST_SEVERITY;INBOUND_DATA_ERROR;MATCHED_VAR;MATCHED_VAR_NAME;MODSEC_BUILD;MSC_PCRE_ERROR;MSC_PCRE_LIMITS_EXCEEDED;MULTIPART_BOUNDARY_QUOTED;MULTIPART_BOUNDARY_WHITESPACE;MULTIPART_CRLF_LF_LINES;MULTIPART_DATA_AFTER;MULTIPART_DATA_BEFORE;MULTIPART_FILE_LIMIT_EXCEEDED;MULTIPART_FILENAME;MULTIPART_HEADER_FOLDING;MULTIPART_INVALID_HEADER_FOLDING;MULTIPART_INVALID_PART;MULTIPART_INVALID_QUOTING;MULTIPART_LF_LINE;MULTIPART_MISSING_SEMICOLON;MULTIPART_NAME;MULTIPART_SEMICOLON_MISSING;MULTIPART_STRICT_ERROR;MULTIPART_UNMATCHED_BOUNDARY;OUTBOUND_DATA_ERROR;PATH_INFO;PERF_ALL;PERF_COMBINED;PERF_GC;PERF_LOGGING;PERF_PHASE1;PERF_PHASE2;PERF_PHASE3;PERF_PHASE4;PERF_PHASE5;PERF_SREAD;PERF_SWRITE;QUERY_STRING;REMOTE_ADDR;REMOTE_HOST;REMOTE_PORT;REMOTE_USER;REQBODY_ERROR;REQBODY_ERROR_MSG;REQBODY_PROCESSOR;REQBODY_PROCESSOR_ERROR;REQBODY_PROCESSOR_ERROR_MSG;REQUEST_BASENAME;REQUEST_BODY;REQUEST_BODY_LENGTH;REQUEST_FILENAME;REQUEST_LINE;REQUEST_METHOD;REQUEST_PROTOCOL;REQUEST_URI;REQUEST_URI_RAW;RESPONSE_BODY;RESPONSE_CONTENT_LENGTH;RESPONSE_CONTENT_TYPE;RESPONSE_PROTOCOL;RESPONSE_STATUS;SCRIPT_BASENAME;SCRIPT_FILENAME;SCRIPT_GID;SCRIPT_GROUPNAME;SCRIPT_MODE;SCRIPT_UID;SCRIPT_USERNAME;SDBM_DELETE_ERROR;SERVER_ADDR;SERVER_NAME;SERVER_PORT;SESSIONID;STATUS;STATUS_LINE;STREAM_INPUT_BODY;STREAM_OUTPUT_BODY;TIME;TIME_DAY;TIME_EPOCH;TIME_HOUR;TIME_MIN;TIME_MON;TIME_SEC;TIME_WDAY;TIME_YEAR;UNIQUE_ID;URLENCODED_ERROR;USERAGENT_IP;USERID;WEBAPPID;WEBSERVER_ERROR_LOG;ARGS;ARGS_GET;ARGS_GET_NAMES;ARGS_NAMES;ARGS_POST;ARGS_POST_NAMES;ENV;FILES;GEO;GLOBAL;IP;MATCHED_VARS;MATCHED_VARS_NAMES;MULTIPART_PART_HEADERS;PERF_RULES;REQUEST_COOKIES;REQUEST_COOKIES_NAMES;REQUEST_HEADERS;REQUEST_HEADERS_NAMES;RESOURCE;RESPONSE_HEADERS;RESPONSE_HEADERS_NAMES;RULE;SESSION;TX;USER;XML
type VariableName string

const (
	ARGS_COMBINED_SIZE               VariableName = "ARGS_COMBINED_SIZE"
	AUTH_TYPE                        VariableName = "AUTH_TYPE"
	DURATION                         VariableName = "DURATION"
	FILES_COMBINED_SIZE              VariableName = "FILES_COMBINED_SIZE"
	FILES_NAMES                      VariableName = "FILES_NAMES"
	FILES_SIZES                      VariableName = "FILES_SIZES"
	FILES_TMP_CONTENT                VariableName = "FILES_TMP_CONTENT"
	FILES_TMPNAMES                   VariableName = "FILES_TMPNAMES"
	FULL_REQUEST                     VariableName = "FULL_REQUEST"
	FULL_REQUEST_LENGTH              VariableName = "FULL_REQUEST_LENGTH"
	HIGHEST_SEVERITY                 VariableName = "HIGHEST_SEVERITY"
	INBOUND_DATA_ERROR               VariableName = "INBOUND_DATA_ERROR"
	MATCHED_VAR                      VariableName = "MATCHED_VAR"
	MATCHED_VAR_NAME                 VariableName = "MATCHED_VAR_NAME"
	MODSEC_BUILD                     VariableName = "MODSEC_BUILD"
	MSC_PCRE_ERROR                   VariableName = "MSC_PCRE_ERROR"
	MSC_PCRE_LIMITS_EXCEEDED         VariableName = "MSC_PCRE_LIMITS_EXCEEDED"
	MULTIPART_BOUNDARY_QUOTED        VariableName = "MULTIPART_BOUNDARY_QUOTED"
	MULTIPART_BOUNDARY_WHITESPACE    VariableName = "MULTIPART_BOUNDARY_WHITESPACE"
	MULTIPART_CRLF_LF_LINES          VariableName = "MULTIPART_CRLF_LF_LINES"
	MULTIPART_DATA_AFTER             VariableName = "MULTIPART_DATA_AFTER"
	MULTIPART_DATA_BEFORE            VariableName = "MULTIPART_DATA_BEFORE"
	MULTIPART_FILE_LIMIT_EXCEEDED    VariableName = "MULTIPART_FILE_LIMIT_EXCEEDED"
	MULTIPART_FILENAME               VariableName = "MULTIPART_FILENAME"
	MULTIPART_HEADER_FOLDING         VariableName = "MULTIPART_HEADER_FOLDING"
	MULTIPART_INVALID_HEADER_FOLDING VariableName = "MULTIPART_INVALID_HEADER_FOLDING"
	MULTIPART_INVALID_PART           VariableName = "MULTIPART_INVALID_PART"
	MULTIPART_INVALID_QUOTING        VariableName = "MULTIPART_INVALID_QUOTING"
	MULTIPART_LF_LINE                VariableName = "MULTIPART_LF_LINE"
	MULTIPART_MISSING_SEMICOLON      VariableName = "MULTIPART_MISSING_SEMICOLON"
	MULTIPART_NAME                   VariableName = "MULTIPART_NAME"
	MULTIPART_SEMICOLON_MISSING      VariableName = "MULTIPART_SEMICOLON_MISSING"
	MULTIPART_STRICT_ERROR           VariableName = "MULTIPART_STRICT_ERROR"
	MULTIPART_UNMATCHED_BOUNDARY     VariableName = "MULTIPART_UNMATCHED_BOUNDARY"
	OUTBOUND_DATA_ERROR              VariableName = "OUTBOUND_DATA_ERROR"
	PATH_INFO                        VariableName = "PATH_INFO"
	PERF_ALL                         VariableName = "PERF_ALL"
	PERF_COMBINED                    VariableName = "PERF_COMBINED"
	PERF_GC                          VariableName = "PERF_GC"
	PERF_LOGGING                     VariableName = "PERF_LOGGING"
	PERF_PHASE1                      VariableName = "PERF_PHASE1"
	PERF_PHASE2                      VariableName = "PERF_PHASE2"
	PERF_PHASE3                      VariableName = "PERF_PHASE3"
	PERF_PHASE4                      VariableName = "PERF_PHASE4"
	PERF_PHASE5                      VariableName = "PERF_PHASE5"
	PERF_SREAD                       VariableName = "PERF_SREAD"
	PERF_SWRITE                      VariableName = "PERF_SWRITE"
	QUERY_STRING                     VariableName = "QUERY_STRING"
	REMOTE_ADDR                      VariableName = "REMOTE_ADDR"
	REMOTE_HOST                      VariableName = "REMOTE_HOST"
	REMOTE_PORT                      VariableName = "REMOTE_PORT"
	REMOTE_USER                      VariableName = "REMOTE_USER"
	REQBODY_ERROR                    VariableName = "REQBODY_ERROR"
	REQBODY_ERROR_MSG                VariableName = "REQBODY_ERROR_MSG"
	REQBODY_PROCESSOR                VariableName = "REQBODY_PROCESSOR"
	REQBODY_PROCESSOR_ERROR          VariableName = "REQBODY_PROCESSOR_ERROR"
	REQBODY_PROCESSOR_ERROR_MSG      VariableName = "REQBODY_PROCESSOR_ERROR_MSG"
	REQUEST_BASENAME                 VariableName = "REQUEST_BASENAME"
	REQUEST_BODY                     VariableName = "REQUEST_BODY"
	REQUEST_BODY_LENGTH              VariableName = "REQUEST_BODY_LENGTH"
	REQUEST_FILENAME                 VariableName = "REQUEST_FILENAME"
	REQUEST_LINE                     VariableName = "REQUEST_LINE"
	REQUEST_METHOD                   VariableName = "REQUEST_METHOD"
	REQUEST_PROTOCOL                 VariableName = "REQUEST_PROTOCOL"
	REQUEST_URI                      VariableName = "REQUEST_URI"
	REQUEST_URI_RAW                  VariableName = "REQUEST_URI_RAW"
	RESPONSE_BODY                    VariableName = "RESPONSE_BODY"
	RESPONSE_CONTENT_LENGTH          VariableName = "RESPONSE_CONTENT_LENGTH"
	RESPONSE_CONTENT_TYPE            VariableName = "RESPONSE_CONTENT_TYPE"
	RESPONSE_PROTOCOL                VariableName = "RESPONSE_PROTOCOL"
	RESPONSE_STATUS                  VariableName = "RESPONSE_STATUS"
	SCRIPT_BASENAME                  VariableName = "SCRIPT_BASENAME"
	SCRIPT_FILENAME                  VariableName = "SCRIPT_FILENAME"
	SCRIPT_GID                       VariableName = "SCRIPT_GID"
	SCRIPT_GROUPNAME                 VariableName = "SCRIPT_GROUPNAME"
	SCRIPT_MODE                      VariableName = "SCRIPT_MODE"
	SCRIPT_UID                       VariableName = "SCRIPT_UID"
	SCRIPT_USERNAME                  VariableName = "SCRIPT_USERNAME"
	SDBM_DELETE_ERROR                VariableName = "SDBM_DELETE_ERROR"
	SERVER_ADDR                      VariableName = "SERVER_ADDR"
	SERVER_NAME                      VariableName = "SERVER_NAME"
	SERVER_PORT                      VariableName = "SERVER_PORT"
	SESSIONID                        VariableName = "SESSIONID"
	STATUS                           VariableName = "STATUS"
	STATUS_LINE                      VariableName = "STATUS_LINE"
	STREAM_INPUT_BODY                VariableName = "STREAM_INPUT_BODY"
	STREAM_OUTPUT_BODY               VariableName = "STREAM_OUTPUT_BODY"
	TIME                             VariableName = "TIME"
	TIME_DAY                         VariableName = "TIME_DAY"
	TIME_EPOCH                       VariableName = "TIME_EPOCH"
	TIME_HOUR                        VariableName = "TIME_HOUR"
	TIME_MIN                         VariableName = "TIME_MIN"
	TIME_MON                         VariableName = "TIME_MON"
	TIME_SEC                         VariableName = "TIME_SEC"
	TIME_WDAY                        VariableName = "TIME_WDAY"
	TIME_YEAR                        VariableName = "TIME_YEAR"
	UNIQUE_ID                        VariableName = "UNIQUE_ID"
	URLENCODED_ERROR                 VariableName = "URLENCODED_ERROR"
	USERAGENT_IP                     VariableName = "USERAGENT_IP"
	USERID                           VariableName = "USERID"
	WEBAPPID                         VariableName = "WEBAPPID"
	WEBSERVER_ERROR_LOG              VariableName = "WEBSERVER_ERROR_LOG"
	ARGS                             VariableName = "ARGS"
	ARGS_GET                         VariableName = "ARGS_GET"
	ARGS_GET_NAMES                   VariableName = "ARGS_GET_NAMES"
	ARGS_NAMES                       VariableName = "ARGS_NAMES"
	ARGS_POST                        VariableName = "ARGS_POST"
	ARGS_POST_NAMES                  VariableName = "ARGS_POST_NAMES"
	ENV                              VariableName = "ENV"
	FILES                            VariableName = "FILES"
	GEO                              VariableName = "GEO"
	GLOBAL                           VariableName = "GLOBAL"
	IP                               VariableName = "IP"
	MATCHED_VARS                     VariableName = "MATCHED_VARS"
	MATCHED_VARS_NAMES               VariableName = "MATCHED_VARS_NAMES"
	MULTIPART_PART_HEADERS           VariableName = "MULTIPART_PART_HEADERS"
	PERF_RULES                       VariableName = "PERF_RULES"
	REQUEST_COOKIES                  VariableName = "REQUEST_COOKIES"
	REQUEST_COOKIES_NAMES            VariableName = "REQUEST_COOKIES_NAMES"
	REQUEST_HEADERS                  VariableName = "REQUEST_HEADERS"
	REQUEST_HEADERS_NAMES            VariableName = "REQUEST_HEADERS_NAMES"
	RESOURCE                         VariableName = "RESOURCE"
	RESPONSE_HEADERS                 VariableName = "RESPONSE_HEADERS"
	RESPONSE_HEADERS_NAMES           VariableName = "RESPONSE_HEADERS_NAMES"
	RULE                             VariableName = "RULE"
	SESSION                          VariableName = "SESSION"
	TX                               VariableName = "TX"
	USER                             VariableName = "USER"
	XML                              VariableName = "XML"
)

// OperatorName is the API spelling of a SecLang operator.
// Aliases (ipMatchF, pmf, strEq, strMatch) are accepted and emitted as the canonical token.

// +kubebuilder:validation:Enum=beginsWith;contains;containsWord;detectSQLi;detectXSS;endsWith;eq;fuzzyHash;ge;geoLookup;gsbLookup;gt;inspectFile;ipMatch;ipMatchFromFile;ipMatchF;le;lt;pm;pmFromFile;pmf;rbl;rsub;rx;rxGlobal;streq;strEq;strmatch;strMatch;unconditionalMatch;validateByteRange;validateDTD;validateHash;validateSchema;validateUrlEncoding;validateUtf8Encoding;verifyCC;verifyCPF;verifySSN;verifySVNR;within
type OperatorName string

const (
	BeginsWith           OperatorName = "beginsWith"
	Contains             OperatorName = "contains"
	ContainsWord         OperatorName = "containsWord"
	DetectSQLi           OperatorName = "detectSQLi"
	DetectXSS            OperatorName = "detectXSS"
	EndsWith             OperatorName = "endsWith"
	Eq                   OperatorName = "eq"
	FuzzyHash            OperatorName = "fuzzyHash"
	Ge                   OperatorName = "ge"
	GeoLookup            OperatorName = "geoLookup"
	GsbLookup            OperatorName = "gsbLookup"
	Gt                   OperatorName = "gt"
	InspectFile          OperatorName = "inspectFile"
	IpMatch              OperatorName = "ipMatch"
	IpMatchFromFile      OperatorName = "ipMatchFromFile"
	IpMatchF             OperatorName = "ipMatchF"
	Le                   OperatorName = "le"
	Lt                   OperatorName = "lt"
	Pm                   OperatorName = "pm"
	PmFromFile           OperatorName = "pmFromFile"
	Pmf                  OperatorName = "pmf"
	Rbl                  OperatorName = "rbl"
	Rsub                 OperatorName = "rsub"
	Rx                   OperatorName = "rx"
	RxGlobal             OperatorName = "rxGlobal"
	Streq                OperatorName = "streq"
	StrEq                OperatorName = "strEq"
	Strmatch             OperatorName = "strmatch"
	StrMatch             OperatorName = "strMatch"
	UnconditionalMatch   OperatorName = "unconditionalMatch"
	ValidateByteRange    OperatorName = "validateByteRange"
	ValidateDTD          OperatorName = "validateDTD"
	ValidateHash         OperatorName = "validateHash"
	ValidateSchema       OperatorName = "validateSchema"
	ValidateUrlEncoding  OperatorName = "validateUrlEncoding"
	ValidateUtf8Encoding OperatorName = "validateUtf8Encoding"
	VerifyCC             OperatorName = "verifyCC"
	VerifyCPF            OperatorName = "verifyCPF"
	VerifySSN            OperatorName = "verifySSN"
	VerifySVNR           OperatorName = "verifySVNR"
	Within               OperatorName = "within"
)

// Transformation is one t: action. normalizePath and normalizePathWin are aliases.

// +kubebuilder:validation:Enum=base64Decode;base64DecodeExt;base64Encode;cmdLine;compressWhitespace;cssDecode;escapeSeqDecode;hexDecode;hexEncode;htmlEntityDecode;jsDecode;length;lowercase;md5;none;normalisePath;normalizePath;normalisePathWin;normalizePathWin;parityEven7bit;parityOdd7bit;parityZero7bit;removeComments;removeCommentsChar;removeNulls;removeWhitespace;replaceComments;replaceNulls;sha1;sqlHexDecode;trim;trimLeft;trimRight;uppercase;urlDecode;urlDecodeUni;urlEncode;utf8toUnicode
type Transformation string

const (
	Base64Decode       Transformation = "base64Decode"
	Base64DecodeExt    Transformation = "base64DecodeExt"
	Base64Encode       Transformation = "base64Encode"
	CmdLine            Transformation = "cmdLine"
	CompressWhitespace Transformation = "compressWhitespace"
	CssDecode          Transformation = "cssDecode"
	EscapeSeqDecode    Transformation = "escapeSeqDecode"
	HexDecode          Transformation = "hexDecode"
	HexEncode          Transformation = "hexEncode"
	HtmlEntityDecode   Transformation = "htmlEntityDecode"
	JsDecode           Transformation = "jsDecode"
	Length             Transformation = "length"
	Lowercase          Transformation = "lowercase"
	Md5                Transformation = "md5"
	None               Transformation = "none"
	NormalisePath      Transformation = "normalisePath"
	NormalizePath      Transformation = "normalizePath"
	NormalisePathWin   Transformation = "normalisePathWin"
	NormalizePathWin   Transformation = "normalizePathWin"
	ParityEven7bit     Transformation = "parityEven7bit"
	ParityOdd7bit      Transformation = "parityOdd7bit"
	ParityZero7bit     Transformation = "parityZero7bit"
	RemoveComments     Transformation = "removeComments"
	RemoveCommentsChar Transformation = "removeCommentsChar"
	RemoveNulls        Transformation = "removeNulls"
	RemoveWhitespace   Transformation = "removeWhitespace"
	ReplaceComments    Transformation = "replaceComments"
	ReplaceNulls       Transformation = "replaceNulls"
	Sha1               Transformation = "sha1"
	SqlHexDecode       Transformation = "sqlHexDecode"
	Trim               Transformation = "trim"
	TrimLeft           Transformation = "trimLeft"
	TrimRight          Transformation = "trimRight"
	Uppercase          Transformation = "uppercase"
	UrlDecode          Transformation = "urlDecode"
	UrlDecodeUni       Transformation = "urlDecodeUni"
	UrlEncode          Transformation = "urlEncode"
	Utf8toUnicode      Transformation = "utf8toUnicode"
)

// DisruptiveActionType is the single disruptive action on chain link 0.

// +kubebuilder:validation:Enum=allow;block;deny;drop;pass;pause;proxy;redirect
type DisruptiveActionType string

const (
	Allow    DisruptiveActionType = "allow"
	Block    DisruptiveActionType = "block"
	Deny     DisruptiveActionType = "deny"
	Drop     DisruptiveActionType = "drop"
	Pass     DisruptiveActionType = "pass"
	Pause    DisruptiveActionType = "pause"
	Proxy    DisruptiveActionType = "proxy"
	Redirect DisruptiveActionType = "redirect"
)

// FlowActionType is skip or skipAfter. chain is rejected: the chain slice emits it.

// +kubebuilder:validation:Enum=skip;skipAfter;chain
type FlowActionType string

const (
	Skip      FlowActionType = "skip"
	SkipAfter FlowActionType = "skipAfter"
	Chain     FlowActionType = "chain"
)

// DataActionType is status or xmlns.

// +kubebuilder:validation:Enum=status;xmlns
type DataActionType string

const (
	Status DataActionType = "status"
	Xmlns  DataActionType = "xmlns"
)

// NonDisruptiveActionType is a side-effect action. sanitize* names are aliases of sanitise*.

// +kubebuilder:validation:Enum=append;prepend;auditlog;capture;ctl;deprecatevar;exec;expirevar;initcol;log;logdata;multiMatch;noauditlog;nolog;sanitiseArg;sanitizeArg;sanitiseMatched;sanitizeMatched;sanitiseMatchedBytes;sanitizeMatchedBytes;sanitiseRequestHeader;sanitizeRequestHeader;sanitiseResponseHeader;sanitizeResponseHeader;setenv;setrsc;setsid;setuid;setvar
type NonDisruptiveActionType string

const (
	Append                 NonDisruptiveActionType = "append"
	Prepend                NonDisruptiveActionType = "prepend"
	Auditlog               NonDisruptiveActionType = "auditlog"
	Capture                NonDisruptiveActionType = "capture"
	Ctl                    NonDisruptiveActionType = "ctl"
	Deprecatevar           NonDisruptiveActionType = "deprecatevar"
	Exec                   NonDisruptiveActionType = "exec"
	Expirevar              NonDisruptiveActionType = "expirevar"
	Initcol                NonDisruptiveActionType = "initcol"
	Log                    NonDisruptiveActionType = "log"
	Logdata                NonDisruptiveActionType = "logdata"
	MultiMatch             NonDisruptiveActionType = "multiMatch"
	Noauditlog             NonDisruptiveActionType = "noauditlog"
	Nolog                  NonDisruptiveActionType = "nolog"
	SanitiseArg            NonDisruptiveActionType = "sanitiseArg"
	SanitizeArg            NonDisruptiveActionType = "sanitizeArg"
	SanitiseMatched        NonDisruptiveActionType = "sanitiseMatched"
	SanitizeMatched        NonDisruptiveActionType = "sanitizeMatched"
	SanitiseMatchedBytes   NonDisruptiveActionType = "sanitiseMatchedBytes"
	SanitizeMatchedBytes   NonDisruptiveActionType = "sanitizeMatchedBytes"
	SanitiseRequestHeader  NonDisruptiveActionType = "sanitiseRequestHeader"
	SanitizeRequestHeader  NonDisruptiveActionType = "sanitizeRequestHeader"
	SanitiseResponseHeader NonDisruptiveActionType = "sanitiseResponseHeader"
	SanitizeResponseHeader NonDisruptiveActionType = "sanitizeResponseHeader"
	Setenv                 NonDisruptiveActionType = "setenv"
	Setrsc                 NonDisruptiveActionType = "setrsc"
	Setsid                 NonDisruptiveActionType = "setsid"
	Setuid                 NonDisruptiveActionType = "setuid"
	Setvar                 NonDisruptiveActionType = "setvar"
)

// CtlPrefixes are the ctl: value prefixes the compiler accepts.
var CtlPrefixes = []string{
	"ruleEngine",
	"ruleRemoveById",
	"ruleRemoveByTag",
	"ruleRemoveByMsg",
	"ruleRemoveTargetById",
	"ruleRemoveTargetByTag",
	"ruleRemoveTargetByMsg",
	"auditEngine",
	"auditLogParts",
	"forceRequestBodyVariable",
	"requestBodyAccess",
	"requestBodyProcessor",
	"requestBodyLimit",
	"responseBodyAccess",
	"responseBodyLimit",
	"forceResponseBodyVariable",
	"debugLogLevel",
	"hashEngine",
	"hashEnforcement",
}

var operatorAlias = map[OperatorName]string{
	IpMatchF: "ipMatchFromFile",
	Pmf:      "pmFromFile",
	StrEq:    "streq",
	StrMatch: "strmatch",
}

var transformationAlias = map[Transformation]string{
	NormalizePath:    "normalisePath",
	NormalizePathWin: "normalisePathWin",
}

var nonDisruptiveAlias = map[NonDisruptiveActionType]string{
	SanitizeArg:            "sanitiseArg",
	SanitizeMatched:        "sanitiseMatched",
	SanitizeMatchedBytes:   "sanitiseMatchedBytes",
	SanitizeRequestHeader:  "sanitiseRequestHeader",
	SanitizeResponseHeader: "sanitiseResponseHeader",
}

// CanonicalOperator returns the SecLang token for an operator name.
func CanonicalOperator(name OperatorName) (string, bool) {
	if a, ok := operatorAlias[name]; ok {
		return a, true
	}
	if operatorKnown(name) {
		return string(name), true
	}
	return "", false
}

func operatorKnown(name OperatorName) bool {
	switch name {
	case BeginsWith, Contains, ContainsWord, DetectSQLi, DetectXSS, EndsWith, Eq, FuzzyHash, Ge, GeoLookup, GsbLookup, Gt, InspectFile, IpMatch, IpMatchFromFile, IpMatchF, Le, Lt, Pm, PmFromFile, Pmf, Rbl, Rsub, Rx, RxGlobal, Streq, StrEq, Strmatch, StrMatch, UnconditionalMatch, ValidateByteRange, ValidateDTD, ValidateHash, ValidateSchema, ValidateUrlEncoding, ValidateUtf8Encoding, VerifyCC, VerifyCPF, VerifySSN, VerifySVNR, Within:
		return true
	default:
		return false
	}
}

// OperatorValueMode reports whether an operator value is forbidden, optional, or required.
// Canonical tokens are compared, so aliases share the mode of the token they emit.
func OperatorValueMode(name OperatorName) (forbidden, optional bool, ok bool) {
	token, ok := CanonicalOperator(name)
	if !ok {
		return false, false, false
	}
	switch token {
	case "unconditionalMatch", "detectSQLi", "detectXSS", "validateUrlEncoding", "validateUtf8Encoding", "geoLookup":
		return true, false, true
	case "verifyCPF", "verifySSN", "verifySVNR":
		return false, true, true
	default:
		return false, false, true
	}
}

// CanonicalTransformation returns the SecLang t: token.
func CanonicalTransformation(name Transformation) (string, bool) {
	if a, ok := transformationAlias[name]; ok {
		return a, true
	}
	if transformationKnown(name) {
		return string(name), true
	}
	return "", false
}

func transformationKnown(name Transformation) bool {
	switch name {
	case Base64Decode, Base64DecodeExt, Base64Encode, CmdLine, CompressWhitespace, CssDecode, EscapeSeqDecode, HexDecode, HexEncode, HtmlEntityDecode, JsDecode, Length, Lowercase, Md5, None, NormalisePath, NormalizePath, NormalisePathWin, NormalizePathWin, ParityEven7bit, ParityOdd7bit, ParityZero7bit, RemoveComments, RemoveCommentsChar, RemoveNulls, RemoveWhitespace, ReplaceComments, ReplaceNulls, Sha1, SqlHexDecode, Trim, TrimLeft, TrimRight, Uppercase, UrlDecode, UrlDecodeUni, UrlEncode, Utf8toUnicode:
		return true
	default:
		return false
	}
}

// CanonicalNonDisruptive returns the SecLang action token.
func CanonicalNonDisruptive(name NonDisruptiveActionType) (string, bool) {
	if a, ok := nonDisruptiveAlias[name]; ok {
		return a, true
	}
	if nonDisruptiveKnown(name) {
		return string(name), true
	}
	return "", false
}

func nonDisruptiveKnown(name NonDisruptiveActionType) bool {
	switch name {
	case Append, Prepend, Auditlog, Capture, Ctl, Deprecatevar, Exec, Expirevar, Initcol, Log, Logdata, MultiMatch, Noauditlog, Nolog, SanitiseArg, SanitizeArg, SanitiseMatched, SanitizeMatched, SanitiseMatchedBytes, SanitizeMatchedBytes, SanitiseRequestHeader, SanitizeRequestHeader, SanitiseResponseHeader, SanitizeResponseHeader, Setenv, Setrsc, Setsid, Setuid, Setvar:
		return true
	default:
		return false
	}
}

// NonDisruptiveValueMode reports how the action value is used.
// optional is true only for sanitiseMatchedBytes. forbidden is true for flag actions.
func NonDisruptiveValueMode(name NonDisruptiveActionType) (forbidden, optional bool, ok bool) {
	token, ok := CanonicalNonDisruptive(name)
	if !ok {
		return false, false, false
	}
	switch token {
	case "auditlog", "capture", "log", "multiMatch", "noauditlog", "nolog", "sanitiseMatched":
		return true, false, true
	case "sanitiseMatchedBytes":
		return false, true, true
	default:
		return false, false, true
	}
}
