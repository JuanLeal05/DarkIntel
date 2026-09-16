import requests

def probar_conexion():
    url = "https://httpbin.org/get"
    respuesta = requests.get(url)

    print("Código de estado:", respuesta.status_code)
    print("Tipo de contenido:", respuesta.headers.get("Content-Type"))
    print("Primeros 200 caracteres del cuerpo:")
    print(respuesta.text[:200])

if __name__ == "__main__":
    probar_conexion()