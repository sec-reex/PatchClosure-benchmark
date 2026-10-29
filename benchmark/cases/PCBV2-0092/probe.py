from poc_common import post, XXE_SBOM

# Seed path (blocked on v1)
print("=== /parse (seed, expected blocked) ===")
print(post(XXE_SBOM, "v1", "/parse")[:1500])
print()
print("=== /validate (residual sibling path, expected flag) ===")
r = post(XXE_SBOM, "v1", "/validate")
print(r[:3000])
