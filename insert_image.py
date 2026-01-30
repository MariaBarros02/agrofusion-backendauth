import psycopg2

# Conexión a PostgreSQL
conn = psycopg2.connect(
    host="localhost",
    dbname="agrofusion",
    user="postgres",
    password="20221203902",
    port=5432
)

cur = conn.cursor()

# Leer imagen desde tu PC (sin problemas de permisos)
with open(
    r"E:\img_agro\tractor_5090e_campo4_large_94dccff5e815fc6a0861f22279f8ae407d335310.jpg",
    "rb"
) as f:
    image_bytes = f.read()

# UPDATE con BYTEA
cur.execute(
    """
    UPDATE public.af_external_projects
    SET
        project_image = %s,
        project_image_mime_type = %s,
        project_image_name = %s
    WHERE instance_code = %s
    """,
    (
        psycopg2.Binary(image_bytes),
        "image/jpg",
        "principal.jpg",
        "SIGMA"
    )
)

conn.commit()
cur.close()
conn.close()

print("Imagen guardada correctamente ✅")
