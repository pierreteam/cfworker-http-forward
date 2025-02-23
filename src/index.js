export default {
    /**
     * @param {Request} req
     * @param {Env} env
     * @returns
     */
    async fetch(req, env) {
        if (!checkSource(env, req.headers)) {
            return new Response(null, { status: 403, statusText: 'Forbidden' });
        }

        const url = new URL(req.url);
        let path = url.pathname.replace(/^\/+/g, '');

        // 检查路径限制
        if (env.ID) {
            if (!path.startsWith(`${env.ID}/`)) {
                return new Response(null, { status: 403, statusText: 'Forbidden' });
            }
            path = path.slice(env.ID.length);
            path = path.replace(/^\/+/g, '');
        }

        // 解析目标地址
        let target = path;
        if (!target) {
            return new Response(JSON.stringify(req.cf, null, 2), { headers: { 'Content-Type': 'application/json' } });
        }

        // 补充协议
        if (!target.startsWith('http://') && !target.startsWith('https://')) {
            target = `${url.protocol}//${target}${url.search}`;
        } else {
            target = `${target}${url.search}`;
        }

        try {
            const url = new URL(target);

            // 检查目标限制
            if (!checkHostName(url.hostname, env)) {
                return new Response(null, { status: 403, statusText: 'Forbidden' });
            }

            // 过滤掉 Cloudflare 相关的请求头
            const headers = new Headers([...req.headers].filter(([key]) => key.toLowerCase().startsWith('cf-')));

            // 转发请求
            return await forwardRequest(target, {
                method: req.method,
                body: req.body,
                headers: headers,
            });
        } catch (e) {
            return new Response(null, { status: 400, statusText: 'Bad Request' });
        }
    },
};

/**
 * @param {Env} env
 * @param {Headers} headers
 */
function checkSource(env, headers) {
    const { SRC_REGIONS, SRC_IPV4_RANGES, SRC_IPV6_RANGES } = env;
    let checked = false;

    // 判断请求地区限制
    if (SRC_REGIONS && SRC_REGIONS.length > 0) {
        checked = true;
        const region = headers.get('CF-IPCountry');
        if (region && SRC_REGIONS.includes(region)) {
            return true;
        }
    }

    // 判断请求 IP 限制
    const ip = headers.get('CF-Connecting-IP') || '';

    if (SRC_IPV4_RANGES && SRC_IPV4_RANGES.length > 0) {
        checked = true;
        if (ip.indexOf('.') !== -1 && SRC_IPV4_RANGES.some((cidr) => ipv4InCIDR(ip, cidr))) {
            return true;
        }
    }

    if (SRC_IPV6_RANGES && SRC_IPV6_RANGES.length > 0) {
        checked = true;
        if (ip.indexOf(':') !== -1 && SRC_IPV6_RANGES.some((cidr) => ipv6InCIDR(ip, cidr))) {
            return true;
        }
    }

    return !checked;
}

/**
 * @param {string} hostname
 * @param {Env} env
 */
function checkHostName(hostname, env) {
    const { TARGETS } = env;
    let checked = false;

    // 检查转发目标限制
    if (TARGETS && TARGETS.length > 0) {
        checked = true;
        if (TARGETS.some((target) => matchDomain(hostname, target))) {
            return true;
        }
    }

    return !checked;
}

/**
 * 允许跨域
 * @param {Headers} headers
 */
function allowCors(headers) {
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    headers.set('Access-Control-Allow-Headers', '*');
}

/**
 * 劫持重定向
 * @param {Headers} headers
 */
function hijackRedirect(headers) {
    if (headers.has('Location')) {
        const target = encodeURIComponent(headers.get('Location') || '');
        headers.set('Location', `/${target}`);
    }
}

/**
 * 转发请求
 * @param {string|URL} target
 * @param {RequestInit} init
 */
async function forwardRequest(target, init) {
    try {
        const resp = await fetch(target, init);

        const headers = new Headers(resp.headers);

        if ([301, 302, 303, 307, 308].includes(resp.status)) {
            // 重定向处理
            hijackRedirect(headers);
        }

        // 跨域处理
        allowCors(headers);

        return new Response(resp.body, {
            status: resp.status,
            statusText: resp.statusText,
            headers,
        });
    } catch (e) {
        return new Response(null, { status: 500, statusText: 'Internal Server Error' });
    }
}

/**
 * @param {string} ip
 * @param {string} cidr
 * @returns
 */
function ipv4InCIDR(ip, cidr) {
    const [base, prefix] = cidr.split('/');
    const mask = -1 << (32 - parseInt(prefix, 10));
    return (ipv4ToInt(base) & mask) === (ipv4ToInt(ip) & mask);
}

/**
 * @param {string} ip
 * @returns
 */
function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
}

/**
 *
 * @param {string} ip
 * @param {string} cidr
 * @returns
 */
function ipv6InCIDR(ip, cidr) {
    const [base, prefix] = cidr.split('/');
    const mask = ipv6Mask(parseInt(prefix, 10));
    const bNums = ipv6ToIntArray(base);
    const iNums = ipv6ToIntArray(ip);
    for (let i = 0; i < 8; i++) {
        if ((mask[i] & bNums[i]) !== (mask[i] & iNums[i])) {
            return false;
        }
    }
    return true;
}
/**
 * @param {string} ip
 * @returns
 */

function ipv6ToIntArray(ip) {
    const nums = [0, 0, 0, 0, 0, 0, 0, 0];
    const parts = ip.split(':');
    let zeros = 8 - parts.length;
    let i = 0;
    for (const part of parts) {
        if (part === '') {
            i += zeros + 1;
            zeros = 0;
        } else {
            nums[i++] = parseInt(part, 16) & 0xffff;
        }
    }
    return nums;
}

/**
 * @param {number} prefix
 * @returns
 */
function ipv6Mask(prefix) {
    const nums = [0, 0, 0, 0, 0, 0, 0, 0];
    for (let i = 0; i < 8 && prefix > 0; i++) {
        if (prefix >= 16) {
            nums[i] = 0xffff;
        } else {
            nums[i] = (0xffff << (16 - prefix)) & 0xffff;
        }
        prefix -= 16;
    }
    return nums;
}

/**
 * @param {string} domain
 * @param {string} pattern
 * @returns
 */
function matchDomain(domain, pattern) {
    if (pattern.startsWith('.')) {
        return domain.endsWith(pattern) || domain === pattern.slice(1);
    } else {
        return domain === pattern;
    }
}
