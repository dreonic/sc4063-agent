import os, glob

src_dir = r'D:\NTU\NTU-Mods-Async\Y4S2\SC4063\project\forensic_agent\forensic_agent\analyzers'
dst_dir = r'D:\NTU\NTU-Mods-Async\Y4S2\SC4063\project\sc4063-agent\agent\analyzers'

files = glob.glob(os.path.join(src_dir, '*.py'))
count = 0
for f in files:
    dst_f = os.path.join(dst_dir, os.path.basename(f))
    with open(f, 'r', encoding='utf-8') as src:
        content = src.read()
    content = content.replace('_sorted.log', '.log')
    with open(dst_f, 'w', encoding='utf-8') as dst:
        dst.write(content)
    count += 1
print(f'Done copying and patching {count} files.')
