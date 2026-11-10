import { Card, CardHeader, CardTitle, CardContent } from "../components/Card";

export default function Iam() {
  return (
    <div>
      <h1 className="h2 fw-bold text-light mb-3">IAM Management</h1>
      <p className="text-body-secondary mb-4">
        Attach Policy, Add to Group forms will go here.
      </p>
      <Card className="border-secondary">
        <CardHeader>
          <CardTitle>Placeholder</CardTitle>
        </CardHeader>
        <CardContent>IAM content (next prompt).</CardContent>
      </Card>
    </div>
  );
}
