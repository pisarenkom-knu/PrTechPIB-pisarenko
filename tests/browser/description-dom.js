// ЛР 5 - DOM-регресія для /browser-lab.html, запуск цілком у Console після входу Alice або Morgan
// Основа - resources/copyable/description-dom.js, додано коментарі, повторний render і позитивні рядки
// Перед запуском оновити сторінку, вставити Guid запису з marker в описі, "Прочитати" не натискати
await (async () => {
  const commentFixtureId = "20000000-0000-0000-0000-000000000001";
  const commentMarkerId = "30000000-0000-0000-0000-000000000005";
  const positiveText = `Користувач O'Brien написав "терміново", 5 < 7 і 9 > 3, Київ - Ω ї є ґ, <b>жирний</b> текст`;
  const target = document.querySelector("#lab05-marker-target");
  const results = [];
  const check = (name, condition) => results.push({ check: name, result: condition ? "PASS" : "FAIL" });
  const wait = () => new Promise(resolve => setTimeout(resolve, 500));
  const read = async id => {
    const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
    if (response.status !== 200) throw new Error(`Unexpected HTTP ${response.status} for ${id}`);
    return response.json();
  };
  const render = async id => {
    target.removeAttribute("data-lab05-marker");
    document.querySelector("#incident-id").value = id;
    await load();
    await wait();
  };

  // Опис - той самий запис із marker, значення API порівнюється з DOM
  const descriptionId = document.querySelector("#incident-id").value.trim();
  if (!descriptionId) throw new Error("Enter the fixture Guid");
  if (target.getAttribute("data-lab05-marker") !== null) throw new Error("Reload before test");
  const descriptionData = await read(descriptionId);
  if (!descriptionData.description.includes("data-lab05-marker")) throw new Error("Wrong fixture");
  await render(descriptionId);
  const description = document.querySelector("#description");
  check("description: textContent === API description", description.textContent === descriptionData.description);
  check("description: no HTML elements", description.childElementCount === 0);
  check("description: marker not executed", target.getAttribute("data-lab05-marker") === null);

  // Коментарі - seed-коментар 30...0005 з marker
  const commentData = await read(commentFixtureId);
  const markerComment = commentData.comments.find(comment => comment.id === commentMarkerId);
  if (!markerComment) throw new Error("Seed comment 30...0005 missing, run reset");
  await render(commentFixtureId);
  const paragraphs = [...document.querySelectorAll("#comments > p")];
  check("comments: one <p> per API comment", paragraphs.length === commentData.comments.length);
  check("comments: every text equals API text",
    paragraphs.every((paragraph, index) => paragraph.textContent === commentData.comments[index].text));
  check("comments: no HTML elements inside <p>", paragraphs.every(paragraph => paragraph.childElementCount === 0));
  check("comments: marker not executed", target.getAttribute("data-lab05-marker") === null);

  // Повторний render того самого запису без дублювання
  await render(commentFixtureId);
  check("re-render: comments not duplicated",
    document.querySelectorAll("#comments > p").length === commentData.comments.length);

  // Позитивний рядок - створюється новий запис з унікальною назвою, бо T-03 дає 409 на повтор
  const created = await fetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: `DOM-тест ${Date.now()}`, description: positiveText,
      severity: "Low", occurredAtUtc: new Date().toISOString() })
  });
  if (created.status !== 201) throw new Error(`Unexpected HTTP ${created.status} on create`);
  const positiveId = (await created.json()).id;
  const positiveData = await read(positiveId);
  await render(positiveId);
  check("positive: API value unchanged", positiveData.description === positiveText);
  check("positive: DOM text equals input", description.textContent === positiveText);
  check("positive: <b> stays text", description.childElementCount === 0);

  console.table(results);
  const failed = results.filter(item => item.result === "FAIL").length;
  console.log(failed === 0
    ? `PASS: ${results.length} checks, description and comments rendered as plain text`
    : `FAIL: ${failed} of ${results.length} checks`);
})();
