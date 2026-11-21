import { createRoot } from 'react-dom/client';
import { useState } from 'react';
import './index.css';
import { Button, Field, Panel, Tabs, Chip, Select, FileInput, Check, TagInput, IconButton } from './ui/kit';
import { Switch } from './pages/Signatures';
import { Mark } from './ui/marks';

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return <div className="grid grid-cols-[160px_1fr] items-center gap-4 border-b border-rule/60 py-3"><span className="mono text-2xs uppercase tracking-[0.14em] text-ink-3">{k}</span><div className="flex flex-wrap items-center gap-3">{children}</div></div>;
}
function Sheet() {
  const [tab, setTab] = useState('a'); const [sw, setSw] = useState(true); const [ck, setCk] = useState(true); const [tags, setTags] = useState(['dmz', 'www']); const [sel, setSel] = useState('1');
  return (
    <div className="min-h-dvh bg-bg p-8 text-ink">
      <h1 className="font-display mb-6 text-[36px] leading-none">Kontrolki</h1>
      <Panel title="Przyciski i pola" count={12} actions={<Button size="sm" variant="ghost" icon="download">CSV</Button>}>
        <Row k="primary"><Button variant="primary" icon="play">Uruchom skan</Button><Button variant="primary" className="!bg-primary-hover">hover</Button><Button variant="primary" busy>Zapis</Button><Button variant="primary" disabled>Wyłączony</Button><Button variant="primary" size="sm">Mały</Button></Row>
        <Row k="secondary"><Button icon="plus">Nowy zakres</Button><Button className="!border-ink-3">hover</Button><Button disabled>Wyłączony</Button><Button size="sm" icon="pencil">Edytuj</Button></Row>
        <Row k="ghost"><Button variant="ghost" icon="globe">English</Button><Button variant="ghost" className="!bg-raised !text-ink">hover</Button><IconButton icon="x" label="Zamknij" /></Row>
        <Row k="danger"><Button variant="danger" icon="trash">Usuń zakres</Button><Button variant="dangerSolid" icon="stop">Stop awaryjny</Button></Row>
        <Row k="focus"><Button variant="primary" className="outline outline-[1.5px] outline-offset-2 outline-focus">Fokus</Button><Button className="outline outline-[1.5px] outline-offset-2 outline-focus">Fokus</Button><input className="field max-w-[220px] !border-transparent outline outline-[1.5px] outline-offset-1 outline-focus" defaultValue="10.66.0.0/16" /></Row>
        <Row k="input"><div className="w-[240px]"><Field label="Nazwa"><input className="field" placeholder="np. DMZ" /></Field></div><div className="w-[240px]"><Field label="Zakres" error="Niepoprawny CIDR."><input className="field" aria-invalid="true" defaultValue="10.66.0.0/33" /></Field></div><div className="w-[200px]"><Field label="Wyłączone"><input className="field" disabled defaultValue="tylko odczyt" /></Field></div></Row>
        <Row k="select / file"><div className="w-[200px]"><Select value={sel} onChange={setSel} label="Profil" options={[{ value: '1', label: 'Co 2 minuty' }, { value: '2', label: 'Pełny /16' }]} /></div><div className="w-[320px]"><FileInput file={null} onFile={() => {}} /></div></Row>
        <Row k="textarea / tags"><textarea className="field w-[280px]" rows={3} defaultValue={'10.20.48.0/24\nlab.uczelnia.example'} /><div className="w-[280px]"><TagInput value={tags} onChange={setTags} placeholder="tag" /></div></Row>
        <Row k="check / switch"><Check label="Tylko niepotwierdzone" checked={ck} onChange={setCk} /><Check label="Wyłączone" checked={false} onChange={() => {}} disabled /><Switch checked={sw} onChange={setSw} label="a" /><Switch checked={false} onChange={() => {}} label="b" /></Row>
        <Row k="chips / marks"><Chip>lab</Chip><Chip tone="accent" onRemove={() => {}}>stan: nowe</Chip><Mark glyph="plus" tone="new">nowe</Mark><Mark glyph="minus" tone="gone">zniknęło</Mark><Mark glyph="ring" tone="changed">zmienione</Mark><Mark glyph="wave" tone="unstable">niestabilne</Mark><a className="link">Wszystkie przebiegi</a></Row>
      </Panel>
      <div className="mt-6"><Panel title="Zakładki" flush><Tabs value={tab} onChange={setTab} tabs={[{ id: 'a', label: 'Wpisz ręcznie' }, { id: 'b', label: 'Z pliku CSV lub JSON', count: 3 }, { id: 'c', label: 'crt.sh' }]} /><p className="p-4 text-sm text-ink-2">Treść zakładki.</p></Panel></div>
    </div>
  );
}
createRoot(document.getElementById('root')!).render(<Sheet />);
