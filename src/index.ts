import Server from "@pxe/server";

interface CORS extends Server.Middleware { }

declare namespace CORS {
    /**
     * CORS middleware options
     */
    export interface Options {
        allowOrigins?: string | string[];
        allowMethods?: string[];
        exposeHeaders?: string[];
        maxAge?: number;
        allowCredentials?: boolean;
        allowHeaders?: string[];
    }
}

class CORS extends Function {
    private readonly options: CORS.Options;

    constructor(options?: CORS.Options) {
        super();

        this.options = options ?? {};

        return new Proxy(this, {
            apply(target, thisArg, argArray) {
                return target.invoke(...argArray as [Server.Context, Server.NextFunction, ...any[]])
            },
        });
    }

    async invoke(ctx: Server.Context, next: Server.NextFunction, ...args: any[]) {
        // Headers 
        const headers = {
            "Access-Control-Allow-Methods": this.options.allowMethods?.join(", ") ?? "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        };
        if (this.options.maxAge)
            headers["Access-Control-Max-Age"] = this.options.maxAge;
        if (this.options.allowCredentials)
            headers["Access-Control-Allow-Credentials"] = "true";
        if (this.options.allowHeaders)
            headers["Access-Control-Allow-Headers"] = this.options.allowHeaders.join(", ");
        if (this.options.exposeHeaders)
            headers["Access-Control-Expose-Headers"] = this.options.exposeHeaders.join(", ");

        // Origin
        if (!this.options.allowOrigins)
            this.options.allowOrigins = "*";

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

        // Set the header
        headers["Access-Control-Allow-Origin"] = value;

        // Set headers and continue
        Object.assign(ctx.response.headers, headers);
        await next(...args);
    }
}

export = CORS;