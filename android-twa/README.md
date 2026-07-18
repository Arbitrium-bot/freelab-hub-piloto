# Freela'B Hub Android / Play Store

Este diretório prepara o caminho para publicar o Freela'B Hub como Android usando Trusted Web Activity (TWA), apontando para a produção Render.

## Dados principais

- App: Freela'B Hub
- URL de produção: https://freelab-hub-app.onrender.com
- Pacote sugerido: br.com.freelabhub.app
- Start URL: https://freelab-hub-app.onrender.com/index.html
- Política de privacidade: https://freelab-hub-app.onrender.com/privacy.html
- Termos: https://freelab-hub-app.onrender.com/terms.html
- Exclusão de conta: https://freelab-hub-app.onrender.com/delete-account.html

## Próximos passos para gerar o AAB

1. Instalar Android Studio ou Android SDK no PC.
2. Instalar Node.js ou usar Bubblewrap em ambiente com npm.
3. Rodar `bubblewrap init --manifest=https://freelab-hub-app.onrender.com/manifest.json`.
4. Usar o pacote `br.com.freelabhub.app`.
5. Gerar a chave de upload e guardar a senha com segurança.
6. Copiar o SHA-256 da chave para `../.well-known/assetlinks.json`.
7. Subir o `assetlinks.json` no Render/GitHub.
8. Rodar `bubblewrap build` para gerar o arquivo `.aab`.
9. Enviar o `.aab` para teste interno no Google Play Console.

Sem Android SDK/Gradle instalado neste PC, este repositório fica pronto para a etapa de build, mas o AAB final ainda depende dessas ferramentas locais.
