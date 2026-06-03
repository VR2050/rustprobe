const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
    throw new Error("app root not found");
}

app.innerHTML = `
  <main style="font-family: sans-serif; padding: 24px;">
    <h1>RustProbe UI Shell</h1>
    <p>Dashboard placeholder for flows, objects, alerts, and app metrics.</p>
    <section>
      <h2>Planned panels</h2>
      <ul>
        <li>Application monitoring</li>
        <li>Domain / URL / IP / Port object aggregation</li>
        <li>Alert stream</li>
        <li>CPU and memory trends</li>
      </ul>
    </section>
  </main>
`;
