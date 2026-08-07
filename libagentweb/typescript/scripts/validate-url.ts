import { fetchAgentWebResource, linksByRel } from "../src/index.js";

const url = process.argv[2];
if (!url) {
  console.error("Usage: npm run validate -- <agent-web-resource-url>");
  process.exit(2);
}

const resource = await fetchAgentWebResource(url);
console.log(
  JSON.stringify(
    {
      status: "valid",
      id: resource["@id"],
      kind: resource.agentWeb.kind,
      itemLinks: linksByRel(resource, "item").length,
    },
    null,
    2,
  ),
);
