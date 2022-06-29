import Server from "@pxe/server";

interface CORS extends Server.Middleware { }

declare namespace CORS {
    /**
     * CORS middleware options
     */
    export interface Options {
        /**
         * Access-Control-Allow-Origin specifies either a single origin which tells browsers to allow that origin to access the resource; 
         * or else — for requests without credentials — the "*" wildcard tells browsers to allow any origin to access the resource.
         */
        allowOrigins?: string | string[];

        /**
         * The Access-Control-Allow-Methods header specifies the method or methods allowed when accessing the resource. 
         * This is used in response to a preflight request.
         */
        allowMethods?: string[];

        /**
         * The Access-Control-Expose-Headers header adds the specified headers to the allowlist that 
         * JavaScript (such as `getResponseHeader()`) in browsers is allowed to access.
         */
        exposeHeaders?: string[];

        /**
         * The Access-Control-Max-Age header indicates how long the results of a preflight request can be cached.
         */
        maxAge?: number;

        /**
         * The Access-Control-Allow-Credentials header indicates whether or not the response to the request can be exposed when the credentials flag is true. 
         * When used as part of a response to a preflight request, this indicates whether or not the actual request can be made using credentials. 
         * Note that simple GET requests are not preflighted, and so if a request is made for a resource with credentials, if this header is not 
         * returned with the resource, the response is ignored by the browser and not returned to web content.
         */
        allowCredentials?: boolean;

        /**
         * The Access-Control-Allow-Headers header is used in response to a preflight request 
         * to indicate which HTTP headers can be used when making the actual request.
         */
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