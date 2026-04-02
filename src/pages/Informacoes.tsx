import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, MapPin, User, Crown, Phone, Monitor } from "lucide-react";
import { Link } from "react-router-dom";

const locais = [
  {
    nome: "Responsável Geral",
    descricao: "",
    responsavel: "Yuri Serrão",
    telefone: "48988425163",
    icon: "crown",
  },
  {
    nome: "Carrinho das Areias",
    descricao: "Travessa Caraguatá, 111, Areias do Campeche",
    responsavel: "Eliasar",
    telefone: "48996418726",
    icon: "mappin",
  },
  {
    nome: "Carrinho do Ribeirão da Ilha",
    descricao: "Rodovia Baldicero Filomeno, 4500, Ribeirão da Ilha",
    responsavel: "Yuri Serrão",
    telefone: "48988425163",
    icon: "mappin",
  },
  {
    nome: "Display",
    descricao: "Rodovia Francisco Thomaz dos Santos, 10, Trevo do Erasmo",
    responsavel: "Sarinely",
    telefone: "48992334710",
    icon: "monitor",
  },
];

const iconMap = {
  crown: Crown,
  mappin: MapPin,
  monitor: Monitor,
};

const Informacoes = () => {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-card/95 backdrop-blur-md shadow-sm">
        <div className="mx-auto flex max-w-4xl items-center gap-3 px-4 py-3">
          <Link to="/">
            <Button variant="ghost" size="icon" className="h-9 w-9">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <MapPin className="h-6 w-6 text-primary" />
            <h1 className="text-lg sm:text-xl font-bold text-foreground">Informações dos Locais</h1>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-6 sm:py-8">
        <div className="grid gap-4 sm:gap-6 md:grid-cols-2">
          {locais.map((local) => {
            const Icon = iconMap[local.icon as keyof typeof iconMap] || MapPin;
            return (
              <Card key={local.nome} className="border border-primary/10 shadow-md hover:shadow-lg transition-shadow duration-200 flex flex-col h-full">
                <CardHeader className="bg-primary/5 rounded-t-lg pb-3">
                  <CardTitle className="flex items-center gap-2 text-base sm:text-lg text-primary">
                    <Icon className="h-5 w-5 shrink-0" />
                    {local.nome}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-4 space-y-3 flex-1 flex flex-col justify-between">
                  {local.descricao ? (
                    <p className="text-sm text-muted-foreground leading-relaxed">{local.descricao}</p>
                  ) : (
                    <div />
                  )}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 rounded-lg bg-secondary p-3">
                      <User className="h-4 w-4 text-primary shrink-0" />
                      <div>
                        <p className="text-xs text-muted-foreground">Responsável</p>
                        <p className="font-semibold text-sm text-foreground">{local.responsavel}</p>
                      </div>
                    </div>
                    {local.telefone && (
                      <a
                        href={`tel:${local.telefone}`}
                        className="flex items-center gap-2 rounded-lg bg-primary/10 p-3 hover:bg-primary/20 transition-colors duration-200"
                      >
                        <Phone className="h-4 w-4 text-primary shrink-0" />
                        <span className="text-sm font-medium text-foreground">
                          ({local.telefone.slice(0, 2)}) {local.telefone.slice(2, 7)}-{local.telefone.slice(7)}
                        </span>
                      </a>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </main>
    </div>
  );
};

export default Informacoes;
