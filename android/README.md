# Freela'B Hub Android

Projeto Android inicial para publicar o Freela'B Hub na Play Store como app wrapper da produção Render.

## Requisitos para gerar o AAB

1. Instalar Android Studio.
2. Abrir esta pasta `android` no Android Studio.
3. Deixar o Gradle sincronizar.
4. Criar uma chave de upload em Build > Generate Signed Bundle / APK.
5. Gerar Android App Bundle (`.aab`) para teste interno no Google Play Console.

## URLs obrigatórias da Play

- Política de privacidade: https://freelab-hub-app.onrender.com/privacy.html
- Termos de uso: https://freelab-hub-app.onrender.com/terms.html
- Exclusão de conta: https://freelab-hub-app.onrender.com/delete-account.html

## Observação

Este wrapper usa WebView nativo. Também deixamos `../android-twa` preparado para TWA/Bubblewrap se você preferir publicar como Trusted Web Activity depois de configurar Digital Asset Links.