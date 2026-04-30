import { defineConfig } from "@hey-api/openapi-ts"

export default defineConfig({
  input: "./openapi.json",
  output: "./src/client",
  plugins: [
    {
      name: "@hey-api/client-fetch",
      throwOnError: true,
    },
    "@hey-api/typescript",
    {
      name: "@hey-api/sdk",
      paramsStructure: "flat",
      responseStyle: "data",
      throwOnError: true,
      operations: {
        strategy: "byTags",
        containerName: "{{name}}Service",
        methods: "static",
        nesting: (operation) => {
          let name = operation.operationId ?? operation.id

          for (const tag of operation.tags ?? []) {
            const prefix = `${tag}-`
            if (name.startsWith(prefix)) {
              name = name.slice(prefix.length)
              break
            }
          }

          return [name]
        },
        methodName: { casing: "camelCase" },
      },
    },
    {
      name: "@hey-api/schemas",
      type: "json",
    },
  ],
})
