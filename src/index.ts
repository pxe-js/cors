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
}

function setHeader(headers: Record<string, string>, header: string, value: string | string[]) {
    if (!Array.isArray(value))
        value = [value];

    headers[header] = value.join(", ");
}

class CORS extends Function {
    private readonly options: CORS.Options;

    constructor(options?: CORS.Options) {
        super();

        // Set to default value if no specified
        if (!options)
            options = {};
        if (!options.allowMethods)
            options.allowMethods = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
        if (!options.allowOrigins)
            options.allowOrigins = "*";

        this.options = options;

        return new Proxy(this, {
            apply(target, thisArg, argArray) {
                return target.invoke(...argArray as [Server.Context, Server.NextFunction, ...any[]])
            },
        });
    }

    async invoke(ctx: Server.Context, next: Server.NextFunction, ...args: any[]) {
        // Headers 
        const headers = {};

        if (this.options.maxAge)
            headers["Access-Control-Max-Age"] = this.options.maxAge;
        if (this.options.allowCredentials)
            headers["Access-Control-Allow-Credentials"] = "true";

        if (this.options.allowHeaders)
            setHeader(headers, "Access-Control-Allow-Headers", this.options.allowHeaders);
        if (this.options.exposeHeaders)
            setHeader(headers, "Access-Control-Expose-Headers", this.options.exposeHeaders);
        if (this.options.allowMethods)
            setHeader(headers, "Access-Control-Allow-Methods", this.options.allowMethods);

        // Set the header value
        let value: string;
        if (
            Array.isArray(this.options.allowOrigins)
            && this.options.allowOrigins.includes(ctx.headers().origin)
        )
            value = ctx.headers().origin;
        else
            value = this.options.allowOrigins as string;

        // If value is not all origin
        if (value !== "*")
            headers["Vary"] = "Origin";

        headers["Access-Control-Allow-Origin"] = value;

        // Set headers and continue
        Object.assign(ctx.response.headers, headers);
        await next(...args);
    }
}

export = CORS;