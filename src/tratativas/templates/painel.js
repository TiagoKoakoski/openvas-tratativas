(() => {
  const busca = document.getElementById("busca");
  const nivel = document.getElementById("nivel");
  const host = document.getElementById("host");
  const conta = document.getElementById("conta");
  const acoes = [...document.querySelectorAll(".acao")];
  if (!busca) return;
  const filtrar = () => {
    const termo = busca.value.trim().toLowerCase();
    let visiveis = 0;
    for (const a of acoes) {
      const ok =
        (!nivel.value || a.dataset.nivel === nivel.value) &&
        (!host.value || JSON.parse(a.dataset.hosts).includes(host.value)) &&
        (!termo || a.textContent.toLowerCase().includes(termo));
      a.hidden = !ok;
      visiveis += ok;
    }
    conta.textContent = visiveis === 1 ? "1 ação na lista" : `${visiveis} ações na lista`;
  };
  for (const campo of [busca, nivel, host]) {
    campo.addEventListener("input", filtrar);
    campo.addEventListener("change", filtrar);
  }
  filtrar();
})();
