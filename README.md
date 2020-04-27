# Shamir secret sharing
Shamir´s secret sharing for mnemonics SLIP-0039
https://github.com/satoshilabs/slips/blob/master/slip-0039.md

Librería para la generación del secreto compartido de Shamir, según las especificaciones de SLIP-0039.
La bilioteca puede ser utilizada en Android, asi como aplicaciones desktop. Recomendamos que mire los test para tener una idea del uso de esta biblioteca. Los detalles técnicos están descritos en el enlace indicado mas arriba. Esta biblioteca se ha desarrollado en el marco del proyecto DALPHIE de UBICUA.

La preservación de acivos digitales es una parte esencial de la actividad de los sistemas de información, y mas aun, de sistemas distribuidos. Un método habitual para esta protección, es el uso intensivo de backups. Sin embargo, si el activo es líquido (por ejemplo Bitcoin) o es especialmente sensible a la privacidad de los datos que contienes, todo el contenido puede ser comprometido. El algoritmo
Shamir´s secret sharing (SSS)  permite implementar un mecanismo de recupración de claves (secretos) y, por tanto, de los contenidos, si estos estan protegidas por ls claves, de un modo mas fiable, demonimado también como mecanismo de Recuperación Social de las claves. Esencialmente este mecanismo consiste en distribuir partes encriptadas de un secreto entre varios prticipantes de confianza para su custodia. Ninguno de ellos de forma individual puede recuperar el secreto, sin embargo la cooperacion de un grupo mínimo de participantes, llamado quorum, puede hacerlo.
