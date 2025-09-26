import { defineCollection, z } from "astro:content";

// 3. 定义你的集合
const blog = defineCollection({
  schema: z.object({
    title: z.string(),
    date: z.date(),
  }),
});

export const collections = { blog };
