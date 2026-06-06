// Cloudflare Pages Function — POST/GET /api/waitlist
// Thin adapter; logic lives in functions/_lib/waitlist-core.mjs (unit-tested).
// Requires a KV binding named WAITLIST. Admin GET needs env.ADMIN_TOKEN.
import { handlePost, handleGet } from "../_lib/waitlist-core.mjs";

export const onRequestPost = (ctx) => handlePost(ctx.request, ctx.env);
export const onRequestGet = (ctx) => handleGet(ctx.request, ctx.env);
