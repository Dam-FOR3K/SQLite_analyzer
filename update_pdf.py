import fitz
import sys

def update_pdf(path):
    print(f"Processing {path}")
    doc = fitz.open(path)
    changed = False
    
    for page in doc:
        # Search for instances of v1.9.0 or v1.9.1
        for old_ver in ["v1.9.0", "1.9.0", "v1.9.1", "1.9.1"]:
            rects = page.search_for(old_ver)
            if rects:
                for rect in rects:
                    print(f"Found {old_ver} on page {page.number}")
                    # redact the old version
                    page.add_redact_annot(rect, fill=(1, 1, 1))
                    page.apply_redactions()
                    
                    # insert the new version "v1.9.2" or "1.9.2"
                    new_ver = "v1.9.2" if old_ver.startswith("v") else "1.9.2"
                    # insert text roughly at the same position, adjusting y slightly for baseline
                    page.insert_text((rect.x0, rect.y1 - 2), new_ver, fontsize=11, color=(0,0,0))
                    changed = True
                    
    if changed:
        doc.save(path + ".tmp.pdf")
        doc.close()
        import os
        os.replace(path + ".tmp.pdf", path)
        print(f"Updated {path}")
    else:
        doc.close()
        print(f"No changes in {path}")

update_pdf("Guide_Forensique_SQLite_Carver_Pro_v1.9.2_FR.pdf")
update_pdf("SQLite_Carver_Pro_Forensic_Guide_v1.9.2_EN.pdf")
