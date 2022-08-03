import Server from "@pxe/server";

interface CORS extends Server.Middleware { }

declare namespace CORS {
    /**
     * CORS middleware options
     */
    export interface Options {
        allowOrigins?: string | string[];
        allowMethods?: string | Server.RequestMethod[];
        exposeHeaders?: string | string[];
        maxAge?: number;
        allowCredentials?: boolean;
        allowHeaders?: string | string[];
    }

    export interface Headers extends Record<string, string | number | readonly string[]> { }
}

function setHeader(headers: CORS.Headers, header: string, value: string | string[]) {
    if (!Array.isArray(value))
        value = [value];

    headers[header] = value.join(", ");
}

function parse(options: CORS.Options) {
    // Headers 
    const headers: CORS.Headers = {};

    if (options.maxAge)
        headers["Access-Control-Max-Age"] = options.maxAge;
    if (options.allowCredentials)
        headers["Access-Control-Allow-Credentials"] = "true";

    if (options.allowHeaders)
        setHeader(headers, "Access-Control-Allow-Headers", options.allowHeaders);
    if (options.exposeHeaders)
        setHeader(headers, "Access-Control-Expose-Headers", options.exposeHeaders);
    if (options.allowMethods)
        setHeader(headers, "Access-Control-Allow-Methods", options.allowMethods);

    return headers;
}

class CORS extends Function {
    private readonly headers: CORS.Headers;
    private readonly allowOrigins: string | string[];

    constructor(options?: CORS.Options) {
        super();

        // Set to default value if no specified
        if (!options)
            options = {};
        if (!options.allowMethods)
            options.allowMethods = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
        if (!options.allowOrigins)
            options.allowOrigins = "*";

        this.headers = parse(options);
        this.allowOrigins = options.allowOrigins;

        return new Proxy(this, {
            apply(target, thisArg, argArray) {
                return target.invoke(...argArray as [Server.Context, Server.NextFunction, ...any[]])
            },
        });
    }

    async invoke(ctx: Server.Context, next: Server.NextFunction, ...args: any[]) {
        const requestOrigin = ctx.request.headers.origin;
        const currentHeaders = this.headers;

        // Set the header value
        let value: string;
        if (
            Array.isArray(this.allowOrigins)
            && this.allowOrigins.includes(requestOrigin)
        )
            value = requestOrigin;
        else
            value = this.allowOrigins as string;

        // If value is not all origin
        if (value !== "*")
            currentHeaders["Vary"] = "Origin";

        currentHeaders["Access-Control-Allow-Origin"] = value;

        // Set headers and continue
        Object.assign(ctx.response.headers, currentHeaders);
        await next(...args);
    }
}

export = CORS;