import demoPackage from "../package.json";
import { DemoShell } from "../components/demo-shell";

export default function DemoPage() {
  return <DemoShell version={demoPackage.version} />;
}
