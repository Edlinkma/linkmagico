# Link Mágico v7.0: Plataforma de IA Conversacional

## O que é o Link Mágico?

O Link Mágico v7.0 é uma plataforma inovadora de Inteligência Artificial Conversacional projetada para otimizar a interação com clientes e automatizar processos de vendas. Ele permite a criação de chatbots inteligentes que podem ser integrados a diversas plataformas, oferecendo respostas personalizadas e extraindo informações relevantes de páginas web para enriquecer as conversas. A ferramenta é ideal para empresas e profissionais que buscam escalar suas operações de atendimento e vendas, proporcionando uma experiência fluida e eficiente para o usuário final.

## Como Funciona?

O Link Mágico v7.0 opera através de um fluxo de trabalho intuitivo e poderoso, dividido em etapas chave:

1.  **Validação de API Key:** O acesso à plataforma é protegido por uma API Key exclusiva. Cada usuário deve inserir uma chave válida para prosseguir, garantindo segurança e personalização no uso da ferramenta.

2.  **Consentimento LGPD:** Após a validação da API Key, o usuário é apresentado a um modal de Preferências de Privacidade, em conformidade com a Lei Geral de Proteção de Dados (LGPD). Aqui, o usuário pode revisar a Política de Privacidade e gerenciar seus dados, garantindo transparência e controle sobre as informações.

3.  **Criação do Chatbot:** Na interface principal, o usuário configura seu assistente de vendas inteligente. Isso inclui:
    *   **Nome do Assistente Virtual:** Um identificador para o chatbot.
    *   **URL da Página:** O Link Mágico extrai automaticamente informações de uma URL fornecida, utilizando-as para treinar o chatbot e fornecer respostas contextuais.
    *   **Instruções Personalizadas (opcional):** O usuário pode definir instruções específicas para o comportamento do chatbot, como tom de voz, estilo de resposta e foco em determinados aspectos da página.

4.  **Ativação e Interação do Chatbot:** Uma vez configurado, o chatbot é ativado. A plataforma gera um link direto para o chatbot e, opcionalmente, um código embed para integrar o chatbot flutuante em qualquer site. O chatbot utiliza Modelos de Linguagem Grandes (LLMs) como Groq, OpenRouter e OpenAI para gerar respostas inteligentes e dinâmicas, baseadas nos dados extraídos e nas instruções fornecidas.

5.  **Analytics e Monitoramento:** A plataforma oferece um dashboard para acompanhar o desempenho do chatbot, incluindo o número de chatbots ativos, conversas realizadas, taxa de sucesso e tempo médio de resposta.

## Manual de Uso na Prática

### 1. Acesso à Plataforma

1.  **Insira sua API Key:** Ao acessar a URL da sua instância do Link Mágico (ex: `https://linkmagico-comercial.onrender.com`), você será solicitado a inserir sua API Key. Digite-a no campo indicado e clique em "Acessar Plataforma".

    *   **Como obter uma API Key:** Se você não possui uma API Key, entre em contato com o administrador da plataforma. As chaves são geradas em um formato específico (ex: `LMV7-XXXX-YYYY-ZZZZ`) e podem ser configuradas via variável de ambiente `API_KEYS_JSON` no seu ambiente de deploy (ex: Render.com).

2.  **Preferências de Privacidade (LGPD):** Leia atentamente as informações sobre o uso de dados. Você pode clicar em "Política de Privacidade" e "Excluir meus dados" para mais detalhes. Para continuar, marque a caixa "Confiro que a URL informada é de minha responsabilidade" e clique em "Aceitar e Continuar".

### 2. Criando seu Chatbot Inteligente

1.  **Nome do Assistente Virtual:** No campo "Nome do Assistente Virtual", digite o nome que seu chatbot terá (ex: `@agentedevendas`).

2.  **URL da Página:** No campo "URL da Página", insira o link da página web da qual o chatbot deverá extrair informações para suas respostas. Certifique-se de que a URL esteja correta e acessível publicamente.

3.  **Instruções Personalizadas (opcional):** Utilize este campo para refinar o comportamento do seu chatbot. Exemplos:
    *   `"Sempre responda de forma amigável, consultiva e entusiasmada, mas objetiva."`
    *   `"Diga poucas respostas curtas (2-3 frases), objetivas e sem repetições."`

4.  **Ativar Chatbot Inteligente:** Clique no botão "Ativar Chatbot Inteligente". A plataforma processará a URL, extrairá os dados e configurará seu chatbot.

### 3. Utilizando o Chatbot

Após a ativação, você verá as seguintes informações e opções:

*   **Link do Chatbot:** Um link direto para acessar seu chatbot. Compartilhe este link com seus clientes.
*   **Dados Extraídos:** Um resumo dos dados que foram extraídos da URL fornecida, que o chatbot utilizará como base para suas respostas.
*   **Botões de Redes Sociais:** Botões para compartilhar o link do seu chatbot diretamente em diversas plataformas de redes sociais (WhatsApp, Instagram, Facebook, YouTube, TikTok, Twitter, Kwai, LinkedIn, Telegram, Messenger).
*   **Prompt:** Um botão para acessar o prompt de configuração do chatbot.
*   **Analytics:** Um botão para visualizar as métricas de desempenho do seu chatbot.
*   **Widget Embed Code:** Um código HTML que você pode copiar e colar em seu site para adicionar um chatbot flutuante.

### 4. Interagindo com o Chatbot

*   **Preview do Chatbot:** Na seção "Preview do Chatbot", você pode testar seu assistente virtual em tempo real. Digite suas perguntas no campo "Digite sua pergunta..." e veja as respostas do chatbot.

## Configuração de Variáveis de Ambiente (para Deploy no Render)

Para que o Link Mágico funcione corretamente em um ambiente de produção como o Render, é necessário configurar algumas variáveis de ambiente:

*   `SESSION_SECRET`: Uma chave secreta para a sessão do Express. Pode ser qualquer string aleatória e segura.
*   `API_KEYS_JSON`: Um objeto JSON contendo suas API Keys válidas. Exemplo:
    ```json
    {
        "LMV7-ABC1-DEF2-GHI3": {"nome":"Cliente Teste","plano":"premium","active":true},
        "LMV7-XYZ4-UVW5-RST6": {"nome":"Outro Cliente","plano":"basic","active":true}
    }
    ```
*   `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY`: As chaves de API para os respectivos modelos de linguagem que você deseja utilizar. Pelo menos uma deve ser fornecida.
*   `GROQ_MODEL`, `OPENROUTER_MODEL`, `OPENAI_MODEL`: (Opcional) Modelos específicos a serem usados com cada provedor de LLM.
*   `LOG_LEVEL`: (Opcional) Nível de log (ex: `info`, `warn`, `error`).

## Suporte e Contato

Para dúvidas, problemas ou sugestões, entre em contato com o suporte técnico.

---

**Desenvolvido por Manus AI**
**Versão:** 7.0
