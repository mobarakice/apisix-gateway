local core = require("apisix.core")
local resty_sha256 = require("resty.sha256")
local str = require("resty.string")
local redis = require "resty.redis"
local ngx = ngx
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local ngx_time = ngx.time
local math = math

local schema = {
    type = "object",
    properties = {

    },

}

local _M = {
    version = 0.1,
    priority = 2980,
    name = "csrf",
    schema = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

local function connect_to_redis()
    local red = redis:new()
    red:set_timeout(1000) -- 1 second

    local conn, conn_err = red:connect("redis", 6379)
    if not conn then
        core.log.error("failed to connect: ", conn_err)
        return nil, conn_err
    end
    --local auth, auth_err = red:auth("yourpassword")
    --
    --if not auth then
    --    core.log.error("failed to authenticate: ", auth_err)
    --    return nil, auth_err
    --end

    return red
end

local function save(red, key, value)
    local ok, err = red:set(key, value)
    if not ok then
        core.log.error("failed to set key: ", err)
        return false, err
    end
    return true
end

local function get(red, key)
    local res, err = red:get(key)
    if not res then
        core.log.error("failed to get key: ", err)
        return nil, err
    end

    if res == ngx.null then
        return nil, "key not found"
    end
    return res
end

local function gen_sign(random, expires, key)
    local sha256 = resty_sha256:new()
    key = "testkeyfornow"

    local sign = "{expires:" .. expires .. ",random:" .. random .. ",key:" .. key .. "}"

    sha256:update(sign)
    local digest = sha256:final()

    return str.to_hex(digest)
end

local function gen_csrf_token(conf)
    local random = math.random()
    local timestamp = ngx_time()
    local sign = gen_sign(random, timestamp, conf.key)

    local token = {
        random = random,
        expires = timestamp,
        sign = sign,
    }

    local cookie = ngx_encode_base64(core.json.encode(token))
    return cookie
end

local function check_csrf_token(conf, ctx, token)
    local token_str = ngx_decode_base64(token)
    if not token_str then
        core.log.error("csrf token base64 decode error")
        return false
    end

    local token_table, err = core.json.decode(token_str)
    if err then
        core.log.error("decode token error: ", err)
        return false
    end

    local random = token_table["random"]
    if not random then
        core.log.error("no random in token")
        return false
    end

    local expires = token_table["expires"]
    if not expires then
        core.log.error("no expires in token")
        return false
    end

    local sign = gen_sign(random, expires, conf.key)
    if token_table["sign"] ~= sign then
        core.log.error("Invalid signatures")
        return false
    end

    return true
end

local function csrf_token_generate_and_store_ctx(conf, ctx, red)
    local csrf_token = gen_csrf_token(conf)
    if csrf_token then
        ctx.csrf_token = csrf_token
        local save_result, save_err = save(red, "csrftoken", csrf_token)
        if not save_result then
            return 500, { error_msg = "Failed to save the csrf token" }
        end
    end
    return csrf_token
end

function _M.access(conf, ctx)
    local redis_connection = ngx.thread.spawn(connect_to_redis)
    local ok, red, err = ngx.thread.wait(redis_connection)
    if not ok then
        return 500, { error_msg = "Failed to connect to redis" }
    end

    local header_token = core.request.header(ctx, "sxsrf")
    if header_token and header_token ~= "" then
        local result = check_csrf_token(conf, ctx, header_token)
        local csrf_exist_token, get_err = get(red, "csrftoken")
        if not csrf_exist_token then
            csrf_token_generate_and_store_ctx(conf, ctx, red)
            return 401, { error_msg = "no csrf token in redis" }
        end
        if result and result ~= csrf_exist_token then
            csrf_token_generate_and_store_ctx(conf, ctx, red)
            return 401, { error_msg = "csrf token verification failed" }
        end

    else
        csrf_token_generate_and_store_ctx(conf, ctx, red)
        return 501, { error_msg = "internal server error" }
    end

end

local function ngx_cookie_time(seconds)
    return ngx.cookie_time(seconds)
end

function _M.header_filter(conf, ctx)
    if ctx.csrf_token then
        core.response.add_header("csrf", ctx.csrf_token)
    end
end

return _M