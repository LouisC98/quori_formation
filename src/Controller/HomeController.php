<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomeController extends AbstractController
{
    #[Route('/', name: 'home')]
    public function index(): Response
    {
        $questions = [
            [
                'title' => 'Je suis une question',
                'content' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit. Omnis mollitia in at itaque totam commodi dolore cum accusantium repudiandae quo illum, nihil ullam facilis, placeat unde hic veritatis quia suscipit.',
                'rating' => -20,
                'author' => [
                    'name' => 'Louis Carvalho',
                    'avatar' => 'https://randomuser.me/api/portraits/lego/7.jpg'
                ],
                'nbResponse' => 15
            ],
            [
                'title' => 'Je suis une question de lego chef',
                'content' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit. Omnis mollitia in at itaque totam commodi dolore cum accusantium repudiandae quo illum, nihil ullam facilis, placeat unde hic veritatis quia suscipit.',
                'rating' => 30,
                'author' => [
                    'name' => 'Lego Chief',
                    'avatar' => 'https://randomuser.me/api/portraits/lego/8.jpg'
                ],
                'nbResponse' => 10
            ]
        ];

        return $this->render('home/index.html.twig', [
            'questions' => $questions
        ]);
    }
}
