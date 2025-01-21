-- fxsrf.lua
local core = require("apisix.core")
local bit = require("bit")
--local utf8 = require("utf8")
local bit32 = require("bit32") -- Ensure this module is available for your Lua version
local ngx = ngx
local plugin_name = "fxsrf"
local math = math

local schema = {
    type = "object",
    properties = {
        key = {
            description = "use to generate csrf token",
            type = "string",
        }
    },
    encrypt_fields = { "key" },
    required = { "key" }
}

local _M = {
    version = 0.1,
    priority = 2983, -- Define the priority of your plugin
    name = plugin_name,
    schema = schema,
}

-- Function to execute when the plugin is enabled
function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function get_xor_key(random)
    return math.floor(random % 255)
end

local function xor_char(char, key)
    local char_code = string.byte(char)         -- Convert character to ASCII value
    local xor_result = bit.bxor(char_code, key) -- XOR the ASCII value with the key
    return string.char(xor_result)              -- Convert the result back to a character
end

-- XOR a string with a number
local function xor_text(key, str)
    local result = {}
    core.log.error("key: ", key)
    core.log.error("str: ", str)
    str:gsub(".", function(c)
        local xor = xor_char(c, key)
        table.insert(result, xor)
    end)
    return table.concat(result) -- Combine all characters into a string
end

local function verify_fxsrf(token)
    local token_str = ngx.decode_base64(token)
    if not token_str then
        core.log.error("csrf token base64 decode error")
        return 401, { error_msg = "custom token verification failed" }
    end

    token_str = ngx.decode_base64(token_str)
    if not token_str then
        core.log.error("csrf token base64 decode error")
        return 401, { error_msg = "custom token verification failed" }
    end

    local token_table, err = core.json.decode(token_str)
    if err then
        core.log.error("decode token error: ", err)
        return 401, { error_msg = "decode token json error" }
    end

    core.log.error(token_table.expires)
    core.log.error(token_table.random)
    core.log.error(token_table.sign)

    local key = get_xor_key(token_table.expires, token_table.random)
    core.log.error("xor_key: ", key)

    local sign = ngx.decode_base64(token_table.sign)
    core.log.error("sign: ", sign)

    local xor = xor_text(key, sign)
    if not xor then
        core.log.error("xor operation failed")
        return 401, { error_msg = "xor operation failed" }
    end
    core.log.error("orinal: ", xor)
end

-- Function to check the 'my-app-key' header in each request
function _M.access(conf, ctx)
    local header_token = core.request.header(ctx, "sxsrf")
    core.log.error("header_token: ", header_token)
    if not header_token or header_token == "" then
        core.log.error("xor header missing")
        return 401, { error_msg = "custom token verification failed" }
    end
    verify_fxsrf(header_token)
end

function _M.header_filter(_, _)
end

return _M
