import requests

def obtener_html(url: str) -> str:
    """
    Descarga el HTML crudo de una URL.
    Lanza una excepción si la petición falla.
    """
    respuesta = requests.get(url, timeout=10)
    respuesta.raise_for_status()  # lanza error si el código NO es 200
    return respuesta.text


if __name__ == "__main__":
    url = "https://books.toscrape.com"
    html = obtener_html(url)
    print("Longitud del HTML descargado:", len(html))
    print("Primeros 300 caracteres:")
    print(html[:300])